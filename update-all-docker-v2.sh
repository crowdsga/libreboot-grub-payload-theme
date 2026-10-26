#!/usr/bin/env bash
set -Eeuo pipefail

# Update Docker containers created with `docker run`, using only Docker CLI
# and Python 3 standard library (no Watchtower, jq, pip packages, or downloads).

if ! command -v python3 >/dev/null 2>&1; then
  echo "错误：需要系统自带的 Python 3（仅使用标准库，不需安装第三方包）。" >&2
  exit 1
fi

exec python3 - "$@" <<'PY'
import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

class UpdateError(Exception):
    pass

class Unsupported(UpdateError):
    pass


def run(cmd, *, check=True, capture=True, timeout=None):
    try:
        p = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise UpdateError(f"命令超时：{cmd[0]}")
    if check and p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()
        # Never print command arguments: env variables and other config can be sensitive.
        raise UpdateError(detail[-1800:] or f"命令失败，退出代码 {p.returncode}")
    return p


def docker_json(args):
    p = run(["docker"] + args)
    return json.loads(p.stdout)


def inspect_container(ref):
    arr = docker_json(["inspect", ref])
    if not arr:
        raise UpdateError("Docker 没有返回容器信息")
    return arr[0]


def inspect_image(ref):
    arr = docker_json(["image", "inspect", ref])
    if not arr:
        raise UpdateError("Docker 没有返回镜像信息")
    return arr[0]


def container_name(c):
    return (c.get("Name") or "").lstrip("/") or c.get("Id", "")[:12]


def safe_name(s, limit=100):
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", s).strip(".-_")
    return (s or "container")[:limit]


def env_map(items):
    out = {}
    for item in items or []:
        k, sep, v = item.partition("=")
        out[k] = v if sep else None
    return out


def normalized_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def nonempty(value):
    return value not in (None, "", [], {}, 0, False)


def platform_string(img):
    os_name = img.get("Os")
    arch = img.get("Architecture")
    variant = img.get("Variant")
    if not os_name or not arch:
        return None
    value = f"{os_name}/{arch}"
    if variant:
        value += f"/{variant}"
    return value


def container_platform_unsupported(img):
    p = platform_string(img)
    return p is None


def endpoint_static(endpoint):
    ipam = endpoint.get("IPAMConfig") or {}
    return bool(ipam.get("IPv4Address") or ipam.get("IPv6Address") or ipam.get("LinkLocalIPs"))


def unsupported_reason(c, old_img):
    cfg = c.get("Config") or {}
    h = c.get("HostConfig") or {}
    net = c.get("NetworkSettings") or {}
    networks = net.get("Networks") or {}

    if (c.get("State") or {}).get("Status") == "paused":
        return "容器处于 paused 状态；请先手动恢复运行后再更新"
    if h.get("AutoRemove"):
        return "启用了 --rm/AutoRemove；停止后旧容器可能被 Docker 自动删除"
    if nonempty(h.get("VolumesFrom")):
        return "使用了 --volumes-from；无法可靠地自动重建依赖关系"
    mode = h.get("NetworkMode") or "default"
    if mode.startswith("container:") or mode.startswith("service:"):
        return f"使用网络模式 {mode}；需要先按依赖顺序手动更新"
    if nonempty(h.get("DeviceRequests")):
        return "使用了 GPU/DeviceRequests；脚本为避免丢失设备配置而跳过"
    if cfg.get("ArgsEscaped"):
        return "容器含 ArgsEscaped 特殊参数（通常为 Windows 容器）"
    if nonempty(h.get("Annotations")):
        return "包含 Docker CLI 无法在所有版本中可靠复原的容器 annotations"
    if int(h.get("KernelMemory") or 0) > 0 or int(h.get("KernelMemoryTCP") or 0) > 0:
        return "设置了已废弃/移除的 Kernel Memory 限制"

    old_cfg = old_img.get("Config") or {}
    old_ep = cfg.get("Entrypoint")
    img_ep = old_cfg.get("Entrypoint")
    if old_ep != img_ep and old_ep and len(old_ep) > 1:
        return "容器覆盖了多段 ENTRYPOINT；docker run 的 --entrypoint 无法无损复原"

    old_health = cfg.get("Healthcheck")
    img_health = old_cfg.get("Healthcheck")
    if normalized_json(old_health) != normalized_json(img_health) and old_health:
        test = old_health.get("Test") or []
        if test and test != ["NONE"] and test[0] != "CMD-SHELL":
            return "容器覆盖了 exec 形式的 HEALTHCHECK；CLI 无法保证原样复原"

    # Static addresses can remain allocated to the retained old container and conflict
    # with the new container. Skip rather than silently changing the network identity.
    for net_name, endpoint in networks.items():
        if endpoint_static(endpoint):
            return f"网络 {net_name} 配置了静态 IP/Link-local IP；为避免地址冲突，脚本跳过"
        mac = (endpoint or {}).get("MacAddress") or ""
        if mac and not mac.lower().startswith("02:42:"):
            return f"网络 {net_name} 使用了可能为手动指定的 MAC 地址 {mac}"
        if nonempty((endpoint or {}).get("DriverOpts")):
            return f"网络 {net_name} 配置了 endpoint driver options"

    # Mounts using a CLI-unrepresentable or ambiguous path are skipped safely.
    for m in h.get("Mounts") or []:
        typ = (m.get("Type") or "").lower()
        if typ not in ("bind", "volume", "tmpfs", "image"):
            return f"包含暂不支持的挂载类型 {typ or '(空)'}"
        if "," in str(m.get("Source") or "") or "," in str(m.get("Target") or ""):
            return "挂载路径包含逗号，Docker --mount 无法安全无损地解析"
    for bind in h.get("Binds") or []:
        pieces = str(bind).split(":")
        if len(pieces) < 2 or "," in pieces[0] or "," in pieces[1]:
            return "包含无法安全复原的 bind mount 路径"
    return None


def add_pair(args, flag, value):
    if value is not None:
        args.extend([flag, str(value)])


def add_repeat(args, flag, values):
    for value in values or []:
        if value is not None and value != "":
            args.extend([flag, str(value)])


def duration_ns(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return f"{value}ns"


def add_healthcheck(args, cfg, old_img_cfg):
    hc = cfg.get("Healthcheck")
    img_hc = old_img_cfg.get("Healthcheck")
    if normalized_json(hc) == normalized_json(img_hc) or hc is None:
        return
    test = hc.get("Test") or []
    if test == ["NONE"]:
        args.append("--no-healthcheck")
        return
    if not test:
        return
    # Preflight guarantees that overridden healthchecks use CMD-SHELL.
    add_pair(args, "--health-cmd", test[1])
    for field, flag in (("Interval", "--health-interval"),
                        ("Timeout", "--health-timeout"),
                        ("StartPeriod", "--health-start-period"),
                        ("StartInterval", "--health-start-interval")):
        val = duration_ns(hc.get(field))
        if val:
            args.extend([flag, val])
    retries = hc.get("Retries")
    if retries:
        args.extend(["--health-retries", str(retries)])


def mount_option_arg(m):
    typ = (m.get("Type") or "").lower()
    target = m.get("Target")
    source = m.get("Source")
    if not target:
        raise Unsupported("挂载没有目标路径")
    parts = [f"type={typ}"]
    if typ in ("bind", "volume", "image") and source:
        parts.append("source=" + str(source))
    parts.append("target=" + str(target))
    if m.get("ReadOnly"):
        parts.append("readonly")
    consistency = m.get("Consistency")
    if consistency:
        parts.append("consistency=" + str(consistency))

    if typ == "bind":
        bo = m.get("BindOptions") or {}
        if bo.get("Propagation"):
            parts.append("bind-propagation=" + str(bo["Propagation"]))
        if bo.get("NonRecursive"):
            parts.append("bind-recursive=disabled")
        if bo.get("CreateMountpoint"):
            parts.append("bind-create-src")
    elif typ == "volume":
        vo = m.get("VolumeOptions") or {}
        if vo.get("NoCopy"):
            parts.append("volume-nocopy")
        driver = vo.get("DriverConfig") or {}
        if driver.get("Name"):
            parts.append("volume-driver=" + str(driver["Name"]))
        for k, v in (driver.get("Options") or {}).items():
            if "," in str(k) or "," in str(v):
                raise Unsupported("volume driver option 含逗号，不能安全复原")
            parts.append(f"volume-opt={k}={v}")
        subpath = vo.get("Subpath") or m.get("Subpath")
        if subpath:
            parts.append("volume-subpath=" + str(subpath))
    elif typ == "tmpfs":
        to = m.get("TmpfsOptions") or {}
        size = to.get("SizeBytes")
        if size:
            parts.append("tmpfs-size=" + str(size))
        mode = to.get("Mode")
        if mode:
            parts.append("tmpfs-mode=" + format(int(mode), "o"))
        opts = to.get("Options")
        if opts:
            if isinstance(opts, list):
                opts = ",".join(str(x) for x in opts)
            parts.append("tmpfs-options=" + str(opts))
    elif typ == "image":
        io = m.get("ImageOptions") or {}
        if io.get("Subpath"):
            parts.append("subpath=" + str(io["Subpath"]))
    if any("," in str(x) for x in parts):
        raise Unsupported("挂载参数含逗号，不能安全复原")
    return ",".join(parts)


def network_names_and_primary(c):
    h = c.get("HostConfig") or {}
    networks = c.get("NetworkSettings", {}).get("Networks") or {}
    mode = h.get("NetworkMode") or "default"
    if mode.startswith("container:") or mode.startswith("service:"):
        raise Unsupported(f"使用网络模式 {mode}")
    if mode in ("host", "none"):
        return mode, None, []
    if mode == "default":
        primary = "bridge" if "bridge" in networks else None
    elif mode in networks:
        primary = mode
    elif mode == "bridge":
        primary = "bridge"
    else:
        # May be a custom network not present in inspect for a stopped container.
        primary = mode
    extras = [n for n in networks.keys() if n != primary and n not in ("host", "none")]
    return mode, primary, extras


def aliases_for(endpoint, c):
    old_id = (c.get("Id") or "").lower()
    short_id = old_id[:12]
    original_name = container_name(c)
    hostname = (c.get("Config") or {}).get("Hostname") or ""
    vals = []
    for alias in (endpoint or {}).get("Aliases") or []:
        if not alias:
            continue
        if alias.lower() in (old_id, short_id, original_name.lower(), hostname.lower()):
            continue
        if alias not in vals:
            vals.append(alias)
    return vals


def endpoint_ip_args(endpoint):
    ipam = (endpoint or {}).get("IPAMConfig") or {}
    out = []
    if ipam.get("IPv4Address"):
        out.extend(["--ip", ipam["IPv4Address"]])
    if ipam.get("IPv6Address"):
        out.extend(["--ip6", ipam["IPv6Address"]])
    add_repeat(out, "--link-local-ip", ipam.get("LinkLocalIPs") or [])
    return out


def build_create_args(c, old_img, new_image_ref, platform):
    cfg = c.get("Config") or {}
    h = c.get("HostConfig") or {}
    old_icfg = old_img.get("Config") or {}
    name = container_name(c)
    args = ["docker", "create", "--name", name]

    if platform:
        args.extend(["--platform", platform])

    # Keep standard interactive settings.
    if cfg.get("OpenStdin"):
        args.append("-i")
    if cfg.get("Tty"):
        args.append("-t")
    if cfg.get("StdinOnce"):
        raise Unsupported("StdinOnce 无法通过通用 docker create 参数完全复原")

    # Only pass config values that differed from the old image defaults. This lets
    # new image defaults (CMD, ENTRYPOINT, ENV, labels, etc.) take effect on update.
    old_hostname = cfg.get("Hostname") or ""
    cid_short = (c.get("Id") or "")[:12]
    if old_hostname and old_hostname != cid_short:
        args.extend(["--hostname", old_hostname])
    if cfg.get("Domainname"):
        args.extend(["--domainname", cfg["Domainname"]])
    if cfg.get("User") != old_icfg.get("User"):
        args.extend(["--user", cfg.get("User") or ""])
    if cfg.get("WorkingDir") != old_icfg.get("WorkingDir"):
        args.extend(["--workdir", cfg.get("WorkingDir") or ""])

    image_env = env_map(old_icfg.get("Env"))
    current_env = env_map(cfg.get("Env"))
    for key, value in current_env.items():
        if key not in image_env or image_env.get(key) != value:
            args.extend(["--env", key if value is None else f"{key}={value}"])

    image_labels = old_icfg.get("Labels") or {}
    current_labels = cfg.get("Labels") or {}
    for key, value in current_labels.items():
        if key not in image_labels or image_labels.get(key) != value:
            args.extend(["--label", f"{key}={value}"])

    old_entry = old_icfg.get("Entrypoint") or []
    current_entry = cfg.get("Entrypoint") or []
    if current_entry != old_entry:
        if not current_entry:
            args.extend(["--entrypoint", ""])
        else:
            args.extend(["--entrypoint", current_entry[0]])

    old_cmd = old_icfg.get("Cmd") or []
    current_cmd = cfg.get("Cmd") or []
    cmd_args = []
    if current_cmd != old_cmd:
        if current_cmd:
            cmd_args = list(current_cmd)
        elif old_cmd:
            raise Unsupported("容器显式清空了镜像 CMD，无法通过 docker create 无损表达")

    if cfg.get("StopSignal") and cfg.get("StopSignal") != old_icfg.get("StopSignal"):
        args.extend(["--stop-signal", cfg["StopSignal"]])

    # Published ports.
    if h.get("PublishAllPorts"):
        args.append("-P")
    for cport, mappings in (h.get("PortBindings") or {}).items():
        for mapping in mappings or []:
            host_ip = mapping.get("HostIp") or ""
            host_port = mapping.get("HostPort") or ""
            if ":" in host_ip and not host_ip.startswith("["):
                host_ip = "[" + host_ip + "]"
            if host_ip:
                spec = f"{host_ip}:{host_port}:{cport}"
            elif host_port:
                spec = f"{host_port}:{cport}"
            else:
                spec = cport
            args.extend(["-p", spec])

    old_exposed = set((old_icfg.get("ExposedPorts") or {}).keys())
    for port in (cfg.get("ExposedPorts") or {}).keys():
        if port not in old_exposed:
            args.extend(["--expose", port])

    # Network setup; use static-address support here, though preflight skips those
    # containers to avoid conflicts with the retained old endpoint.
    mode, primary, extras = network_names_and_primary(c)
    if mode in ("host", "none"):
        args.extend(["--network", mode])
    elif primary and (primary != "bridge" or endpoint_static((c.get("NetworkSettings", {}).get("Networks") or {}).get(primary))):
        args.extend(["--network", primary])
    elif mode == "bridge" and primary == "bridge":
        args.extend(["--network", "bridge"])
    if primary and primary in (c.get("NetworkSettings", {}).get("Networks") or {}):
        endpoint = (c.get("NetworkSettings", {}).get("Networks") or {}).get(primary) or {}
        if primary not in ("bridge", "host", "none"):
            for alias in aliases_for(endpoint, c):
                args.extend(["--network-alias", alias])
        # Static addresses were preflighted out, this remains as a defensive check.
        if endpoint_static(endpoint):
            args.extend(endpoint_ip_args(endpoint))

    # Container resource / namespace / security options.
    if h.get("Privileged"):
        args.append("--privileged")
    if h.get("ReadonlyRootfs"):
        args.append("--read-only")
    if h.get("Init"):
        args.append("--init")
    if h.get("OomKillDisable"):
        args.append("--oom-kill-disable")
    if h.get("OomScoreAdj"):
        args.extend(["--oom-score-adj", str(h["OomScoreAdj"])])
    if h.get("Memory"):
        args.extend(["--memory", str(h["Memory"])])
    if h.get("MemoryReservation"):
        args.extend(["--memory-reservation", str(h["MemoryReservation"])])
    if h.get("MemorySwap") and h.get("MemorySwap") != h.get("Memory"):
        args.extend(["--memory-swap", str(h["MemorySwap"])])
    if h.get("MemorySwappiness") is not None and h.get("MemorySwappiness") != 0:
        args.extend(["--memory-swappiness", str(h["MemorySwappiness"])])
    if h.get("CpuShares"):
        args.extend(["--cpu-shares", str(h["CpuShares"])])
    if h.get("NanoCpus"):
        args.extend(["--cpus", f"{h['NanoCpus'] / 1_000_000_000:.9f}".rstrip("0").rstrip(".")])
    else:
        if h.get("CpuPeriod"):
            args.extend(["--cpu-period", str(h["CpuPeriod"])])
        if h.get("CpuQuota"):
            args.extend(["--cpu-quota", str(h["CpuQuota"])])
    if h.get("CpusetCpus"):
        args.extend(["--cpuset-cpus", h["CpusetCpus"]])
    if h.get("CpusetMems"):
        args.extend(["--cpuset-mems", h["CpusetMems"]])
    if h.get("CpuRealtimePeriod"):
        args.extend(["--cpu-rt-period", str(h["CpuRealtimePeriod"])])
    if h.get("CpuRealtimeRuntime"):
        args.extend(["--cpu-rt-runtime", str(h["CpuRealtimeRuntime"])])
    if h.get("PidsLimit") not in (None, 0):
        args.extend(["--pids-limit", str(h["PidsLimit"])])
    if h.get("BlkioWeight"):
        args.extend(["--blkio-weight", str(h["BlkioWeight"])])
    for field, flag in (("BlkioWeightDevice", "--blkio-weight-device"),
                        ("BlkioDeviceReadBps", "--device-read-bps"),
                        ("BlkioDeviceWriteBps", "--device-write-bps"),
                        ("BlkioDeviceReadIOps", "--device-read-iops"),
                        ("BlkioDeviceWriteIOps", "--device-write-iops")):
        for item in h.get(field) or []:
            path = item.get("Path")
            value = item.get("Weight") if field == "BlkioWeightDevice" else (
                item.get("Rate") if field in ("BlkioDeviceReadBps", "BlkioDeviceWriteBps") else item.get("Rate")
            )
            if path and value is not None:
                args.extend([flag, f"{path}:{value}"])
    if h.get("CgroupParent"):
        args.extend(["--cgroup-parent", h["CgroupParent"]])
    if h.get("CgroupnsMode") and h["CgroupnsMode"] != "private":
        args.extend(["--cgroupns", h["CgroupnsMode"]])
    if h.get("PidMode") and h["PidMode"] != "private":
        args.extend(["--pid", h["PidMode"]])
    if h.get("IpcMode") and h["IpcMode"] != "private":
        args.extend(["--ipc", h["IpcMode"]])
    if h.get("UTSMode") and h["UTSMode"] != "private":
        args.extend(["--uts", h["UTSMode"]])
    if h.get("UsernsMode"):
        args.extend(["--userns", h["UsernsMode"]])
    if h.get("Runtime"):
        args.extend(["--runtime", h["Runtime"]])
    if h.get("VolumeDriver"):
        args.extend(["--volume-driver", h["VolumeDriver"]])
    if h.get("Isolation"):
        args.extend(["--isolation", h["Isolation"]])
    if h.get("ShmSize") and h["ShmSize"] != 67108864:
        args.extend(["--shm-size", str(h["ShmSize"])])

    add_repeat(args, "--group-add", h.get("GroupAdd") or [])
    add_repeat(args, "--cap-add", h.get("CapAdd") or [])
    add_repeat(args, "--cap-drop", h.get("CapDrop") or [])
    add_repeat(args, "--security-opt", h.get("SecurityOpt") or [])
    add_repeat(args, "--device-cgroup-rule", h.get("DeviceCgroupRules") or [])
    for d in h.get("Devices") or []:
        spec = d.get("PathOnHost", "")
        if d.get("PathInContainer"):
            spec += ":" + d["PathInContainer"]
        if d.get("CgroupPermissions"):
            spec += ":" + d["CgroupPermissions"]
        if spec:
            args.extend(["--device", spec])

    add_repeat(args, "--dns", h.get("Dns") or [])
    add_repeat(args, "--dns-search", h.get("DnsSearch") or [])
    add_repeat(args, "--dns-option", h.get("DnsOptions") or [])
    add_repeat(args, "--add-host", h.get("ExtraHosts") or [])
    add_repeat(args, "--link", h.get("Links") or [])
    for key, value in (h.get("Sysctls") or {}).items():
        args.extend(["--sysctl", f"{key}={value}"])
    for k, v in (h.get("StorageOpt") or {}).items():
        args.extend(["--storage-opt", f"{k}={v}"])

    # Ulimits.
    for item in h.get("Ulimits") or []:
        if item.get("Name"):
            soft = item.get("Soft")
            hard = item.get("Hard")
            if soft is not None and hard is not None:
                args.extend(["--ulimit", f"{item['Name']}={soft}:{hard}"])
            elif soft is not None:
                args.extend(["--ulimit", f"{item['Name']}={soft}"])

    restart = h.get("RestartPolicy") or {}
    restart_name = restart.get("Name") or "no"
    restart_max = restart.get("MaximumRetryCount") or 0
    if restart_name == "on-failure" and restart_max:
        restart_name += f":{restart_max}"
    args.extend(["--restart", restart_name])
    if h.get("StopTimeout") is not None:
        args.extend(["--stop-timeout", str(h["StopTimeout"])])

    # Logging: preserve driver/options as observed on the old container.
    logcfg = h.get("LogConfig") or {}
    if logcfg.get("Type"):
        args.extend(["--log-driver", logcfg["Type"]])
    for k, v in (logcfg.get("Config") or {}).items():
        args.extend(["--log-opt", f"{k}={v}"])

    # Old `-v` binds, preserving read-only / propagation / SELinux modes.
    covered_targets = set()
    for bind in h.get("Binds") or []:
        args.extend(["-v", bind])
        pieces = bind.split(":")
        if len(pieces) >= 2:
            covered_targets.add(pieces[1])

    # Structured `--mount` options.
    for m in h.get("Mounts") or []:
        target = m.get("Target")
        if target:
            covered_targets.add(target)
        args.extend(["--mount", mount_option_arg(m)])

    # `--tmpfs` mounts are represented separately in HostConfig on some Docker versions.
    for dest, opts in (h.get("Tmpfs") or {}).items():
        if dest in covered_targets:
            continue
        spec = str(dest)
        if opts:
            spec += ":" + str(opts)
        args.extend(["--tmpfs", spec])
        covered_targets.add(dest)

    # Preserve anonymous volumes created by an image VOLUME declaration. Reuse the
    # original volume name so data is not silently replaced with a new empty volume.
    for m in c.get("Mounts") or []:
        dest = m.get("Destination")
        if not dest or dest in covered_targets:
            continue
        typ = (m.get("Type") or "").lower()
        if typ == "volume":
            volname = m.get("Name")
            if not volname:
                raise Unsupported(f"挂载点 {dest} 的匿名 Volume 名称不可用")
            spec = f"type=volume,source={volname},target={dest}"
            if not m.get("RW", True):
                spec += ",readonly"
            if "," in spec:
                raise Unsupported(f"挂载点 {dest} 无法安全复原")
            args.extend(["--mount", spec])
            covered_targets.add(dest)
        elif typ == "bind":
            src = m.get("Source")
            if not src:
                raise Unsupported(f"Bind 挂载点 {dest} 没有来源路径")
            spec = f"type=bind,source={src},target={dest}"
            if not m.get("RW", True):
                spec += ",readonly"
            if m.get("Propagation"):
                spec += ",bind-propagation=" + str(m["Propagation"])
            if "," in spec:
                raise Unsupported(f"挂载点 {dest} 无法安全复原")
            args.extend(["--mount", spec])
            covered_targets.add(dest)
        elif typ == "tmpfs":
            # Most tmpfs mounts were handled via HostConfig.Tmpfs or Mounts above.
            continue
        else:
            raise Unsupported(f"挂载点 {dest} 的类型 {typ} 无法安全复原")

    add_healthcheck(args, cfg, old_icfg)

    args.append(new_image_ref)
    args.extend(cmd_args)

    # Networks other than the initial network are attached after docker create.
    network_ops = []
    networks = c.get("NetworkSettings", {}).get("Networks") or {}
    mode, primary, extras = network_names_and_primary(c)
    for net_name in extras:
        endpoint = networks.get(net_name) or {}
        op = ["docker", "network", "connect"]
        if endpoint.get("IPAMConfig"):
            ipam = endpoint.get("IPAMConfig") or {}
            if ipam.get("IPv4Address"):
                op.extend(["--ip", ipam["IPv4Address"]])
            if ipam.get("IPv6Address"):
                op.extend(["--ip6", ipam["IPv6Address"]])
            add_repeat(op, "--link-local-ip", ipam.get("LinkLocalIPs") or [])
        for alias in aliases_for(endpoint, c):
            op.extend(["--alias", alias])
        op.extend([net_name, name])
        network_ops.append(op)

    return args, network_ops


def unique_backup_name(name, stamp, short_id):
    base = f"{name[:150]}-old-{stamp}-{short_id[:6]}"
    candidate = base[:240]
    n = 1
    while run(["docker", "container", "inspect", candidate], check=False).returncode == 0:
        n += 1
        candidate = f"{base[:225]}-{n}"
    return candidate


def write_text(path, value):
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)
    os.chmod(path, 0o600)


def save_snapshot(c, backup_dir):
    name = container_name(c)
    stem = safe_name(name + "_" + c.get("Id", "")[:12])
    target = os.path.join(backup_dir, stem)
    os.makedirs(target, mode=0o700, exist_ok=True)
    write_text(os.path.join(target, "inspect.json"), json.dumps(c, indent=2, ensure_ascii=False) + "\n")
    if (c.get("State") or {}).get("Running"):
        logs = run(["docker", "logs", "--timestamps", "--tail", "3000", c["Id"]], check=False)
        write_text(os.path.join(target, "logs.txt"), (logs.stdout or "") + (logs.stderr or ""))
    return target


def get_current_image_id(ref):
    try:
        return inspect_image(ref).get("Id")
    except Exception:
        return None


def restore_old(old_id, backup_name, original_name, was_running):
    # New container is removed by caller before invoking this function.
    r = run(["docker", "rename", backup_name, original_name], check=False)
    if r.returncode != 0:
        print(f"    警告：无法把备份容器改回 {original_name}：{(r.stderr or '').strip()}")
        return False
    if was_running:
        r = run(["docker", "start", original_name], check=False)
        if r.returncode != 0:
            print(f"    警告：旧容器已恢复名称，但启动失败：{(r.stderr or '').strip()}")
            return False
    return True


def state_of(name):
    c = inspect_container(name)
    state = c.get("State") or {}
    return bool(state.get("Running")), ((state.get("Health") or {}).get("Status"))


def wait_for_start(name, seconds=8):
    deadline = time.time() + seconds
    last_running = False
    while time.time() < deadline:
        try:
            running, health = state_of(name)
        except Exception:
            return False, "无法检查新容器状态"
        last_running = running
        if not running:
            c = inspect_container(name)
            state = c.get("State") or {}
            return False, f"容器启动后退出（状态={state.get('Status')}，退出码={state.get('ExitCode')}）"
        if health == "unhealthy":
            return False, "容器健康检查状态为 unhealthy"
        if health == "healthy":
            return True, "healthy"
        time.sleep(1)
    if last_running:
        return True, "仍在运行（没有健康检查或健康检查仍在启动）"
    return False, "启动后未保持运行"


def update_one(cid, backup_dir, stamp, pull_cache):
    c = inspect_container(cid)
    name = container_name(c)
    state = c.get("State") or {}
    was_running = bool(state.get("Running"))
    cfg = c.get("Config") or {}
    image_ref = cfg.get("Image") or ""
    old_image_id = c.get("Image") or ""
    print(f"\n[{name}] 状态={'运行中' if was_running else '已停止'}；镜像={image_ref}")

    if not image_ref or image_ref.startswith("sha256:") or "@sha256:" in image_ref:
        print("  跳过：容器使用不可变的 image ID/digest 引用，无法自动判断上游新版本。")
        return "skipped"
    try:
        old_img = inspect_image(old_image_id)
    except Exception as e:
        print(f"  跳过：无法读取原镜像配置：{e}")
        return "skipped"

    reason = unsupported_reason(c, old_img)
    if reason:
        print(f"  跳过：{reason}")
        return "skipped"

    platform = platform_string(old_img)
    cache_key = (image_ref, platform or "")
    if cache_key not in pull_cache:
        print(f"  拉取镜像（平台 {platform or 'Docker 默认平台'}）……")
        pull_cmd = ["docker", "pull"]
        if platform:
            pull_cmd.extend(["--platform", platform])
        pull_cmd.append(image_ref)
        p = run(pull_cmd, check=False, timeout=1800)
        combined = (p.stdout or "") + (p.stderr or "")
        if combined.strip():
            # Docker pull output is operational output; do not echo any container env.
            for line in combined.rstrip().splitlines()[-20:]:
                print("    " + line)
        pull_cache[cache_key] = p.returncode == 0
    if not pull_cache[cache_key]:
        print("  跳过：docker pull 失败（可能是私有仓库认证、网络或本地镜像标签问题）。")
        return "failed"

    new_image_id = get_current_image_id(image_ref)
    if not new_image_id:
        print("  跳过：拉取后无法检查新镜像。")
        return "failed"
    if new_image_id == old_image_id:
        print("  已是最新：镜像 ID 没有变化。")
        return "up-to-date"

    try:
        create_args, network_ops = build_create_args(c, old_img, image_ref, platform)
    except Unsupported as e:
        print(f"  跳过：{e}")
        return "skipped"

    snapshot_dir = save_snapshot(c, backup_dir)
    backup_img_tag = f"local/docker-update-backup-{safe_name(name.lower())}:{stamp}"
    tag_result = run(["docker", "image", "tag", old_image_id, backup_img_tag], check=False)
    if tag_result.returncode != 0:
        print(f"  失败：无法给旧镜像创建备份标签，未修改容器。{(tag_result.stderr or '').strip()}")
        return "failed"

    backup_name = unique_backup_name(name, stamp, c.get("Id", ""))
    original_id = c.get("Id")
    if was_running:
        timeout_s = (c.get("HostConfig") or {}).get("StopTimeout")
        stop_cmd = ["docker", "stop"]
        if timeout_s is not None:
            stop_cmd.extend(["--time", str(timeout_s)])
        stop_cmd.append(original_id)
        stopped = run(stop_cmd, check=False, timeout=180)
        if stopped.returncode != 0:
            print(f"  失败：无法停止旧容器，未继续更新：{(stopped.stderr or '').strip()}")
            return "failed"

    renamed = False
    new_created = False
    try:
        run(["docker", "rename", original_id, backup_name])
        renamed = True
        p = run(create_args, check=True, timeout=180)
        new_id = (p.stdout or "").strip()
        if not new_id:
            raise UpdateError("docker create 没有返回新容器 ID")
        new_created = True

        for op in network_ops:
            nr = run(op, check=False, timeout=120)
            if nr.returncode != 0:
                raise UpdateError("连接附加网络失败：" + ((nr.stderr or "").strip()[-800:]))

        if was_running:
            sr = run(["docker", "start", name], check=False, timeout=180)
            if sr.returncode != 0:
                raise UpdateError("新容器启动失败：" + ((sr.stderr or "").strip()[-800:]))
            ok, why = wait_for_start(name, seconds=8)
            if not ok:
                logs = run(["docker", "logs", "--tail", "80", name], check=False)
                if (logs.stdout or "").strip():
                    print("    新容器最近日志：")
                    for line in (logs.stdout or "").rstrip().splitlines()[-30:]:
                        print("      " + line)
                raise UpdateError(why)
        print("  更新成功。")
        print(f"    旧容器：{backup_name}")
        print(f"    旧镜像备份标签：{backup_img_tag}")
        print(f"    配置/日志备份：{snapshot_dir}")
        if not was_running:
            print("    原容器之前处于停止状态；新容器已创建但没有启动。")
        return "updated"

    except Exception as e:
        print(f"  更新失败：{e}")
        if new_created:
            run(["docker", "rm", "-f", name], check=False, timeout=120)
        restored = False
        if renamed:
            restored = restore_old(original_id, backup_name, name, was_running)
        if restored:
            print("  已尝试回滚到旧容器。请检查旧容器状态与应用数据。")
        else:
            print(f"  请手动检查备份容器：{backup_name}")
        return "failed"


def main():
    parser = argparse.ArgumentParser(
        description="使用 Docker CLI + Python 3 标准库更新 docker run 创建的容器；不依赖 Watchtower/jq/第三方 Python 包。"
    )
    parser.add_argument("--yes", "-y", action="store_true", help="跳过确认提示")
    parser.add_argument("--dry-run", action="store_true", help="仅列出容器，不拉取镜像或修改任何内容")
    parser.add_argument("--running-only", action="store_true", help="只处理正在运行的容器；默认也检查已停止的容器")
    parser.add_argument("--backup-root", default=os.environ.get("DOCKER_UPDATE_BACKUP_ROOT", os.path.join(Path.home(), "docker-update-backups")), help="备份根目录（默认 ~/docker-update-backups）")
    opts = parser.parse_args()

    if not shutil.which("docker"):
        print("错误：找不到 docker 命令。", file=sys.stderr)
        return 2

    v = run(["docker", "version", "--format", "{{.Client.Version}} / {{.Server.Version}}"], check=False)
    if v.returncode != 0:
        print("错误：无法连接 Docker daemon。请确认 Docker 正常运行且当前用户有权限。", file=sys.stderr)
        if (v.stderr or "").strip():
            print((v.stderr or "").strip(), file=sys.stderr)
        return 2

    ids_cmd = ["docker", "ps", "-q" if opts.running_only else "-aq", "--no-trunc"]
    ids_p = run(ids_cmd, check=True)
    ids = [x.strip() for x in (ids_p.stdout or "").splitlines() if x.strip()]
    if not ids:
        print("没有找到要处理的容器。")
        return 0

    print("Docker 版本：" + (v.stdout or "").strip())
    print(f"容器数量：{len(ids)}（{'仅运行中' if opts.running_only else '包含运行中与已停止'}）")
    if opts.dry_run:
        print("\nDry run：不会拉取镜像、停止容器或改动配置。")
        for cid in ids:
            try:
                c = inspect_container(cid)
                cfg = c.get("Config") or {}
                state = (c.get("State") or {}).get("Status", "unknown")
                print(f"  {container_name(c)} | {state} | {cfg.get('Image', '(unknown)')}")
            except Exception as e:
                print(f"  {cid[:12]} | 无法读取：{e}")
        return 0

    if not opts.yes:
        print("\n将逐个拉取镜像；发现镜像 ID 变化时会重建容器。")
        print("旧容器和旧镜像会保留以便手动回滚；容器可能短暂中断。")
        print("脚本不会备份应用数据库/业务数据；重要服务请先做应用级备份。")
        print("无法安全复原的高级配置（如 --rm、--volumes-from、静态 IP、GPU 请求等）会跳过。")
        answer = input("输入 yes 确认继续：").strip()
        if answer != "yes":
            print("已取消，没有修改容器。")
            return 0

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = os.path.abspath(os.path.expanduser(os.path.join(opts.backup_root, stamp)))
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(backup_dir, 0o700)
    except OSError:
        pass
    print(f"\n配置备份目录：{backup_dir}")
    print("注意：inspect.json 可能包含密码、Token 等敏感信息，请妥善保管。")

    counts = {"updated": 0, "up-to-date": 0, "skipped": 0, "failed": 0}
    pull_cache = {}
    for i, cid in enumerate(ids, 1):
        print(f"\n========== [{i}/{len(ids)}] ==========")
        try:
            result = update_one(cid, backup_dir, stamp, pull_cache)
        except Exception as e:
            print(f"  未处理：{e}")
            result = "failed"
        counts[result] = counts.get(result, 0) + 1

    print("\n========== 更新汇总 ==========")
    print(f"更新成功：{counts['updated']}")
    print(f"已经最新：{counts['up-to-date']}")
    print(f"安全跳过：{counts['skipped']}")
    print(f"失败：{counts['failed']}")
    print(f"配置备份：{backup_dir}")
    print("旧容器名称带有 -old- 时间戳；验证服务正常前不要删除。")
    return 0 if counts["failed"] == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
PY
