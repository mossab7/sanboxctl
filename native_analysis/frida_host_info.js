/*
 * Read-only native host-information observer.
 *
 * This agent does not alter arguments, return values, memory, or target files.
 * It deliberately records categories and redacted metadata rather than values
 * that might contain credentials, host identifiers, or remote endpoints.
 */
(function () {
  'use strict';

  let options = { level: 'focus', maxEvents: 4000, maxStack: 10, categories: [], captureGpuValues: false };
  let installed = false;
  let emitted = 0;
  let dropped = false;
  const trackedFds = new Map();
  const hookedAddresses = new Set();

  function find(name) {
    try { return Module.findGlobalExportByName(name); } catch (_) { return null; }
  }
  function text(pointer) {
    try { return pointer.isNull() ? null : pointer.readUtf8String(); } catch (_) { return null; }
  }
  function category(path) {
    if (!path) return null;
    if (path === '/etc/machine-id' || path === '/var/lib/dbus/machine-id') return 'machine-id';
    if (path === '/etc/hostname') return 'hostname';
    if (path.startsWith('/sys/class/dmi') || path.startsWith('/sys/devices/virtual/dmi')) return 'dmi';
    if (path.startsWith('/sys/bus/pci') || path.startsWith('/sys/devices/pci') || path.startsWith('/sys/dev/char')) return 'pci-or-drm-topology';
    if (path.startsWith('/sys/class/drm') || path.startsWith('/sys/kernel/debug/dri')) return 'drm-sysfs';
    if (path.startsWith('/dev/dri/')) return 'drm-device';
    if (path.startsWith('/dev/disk/')) return 'disk-device';
    if (path.startsWith('/run/udev')) return 'udev';
    if (path === '/proc/cpuinfo' || path.startsWith('/proc/cpuinfo/')) return 'proc-cpu';
    if (path === '/proc/meminfo') return 'proc-memory';
    if (path === '/proc/net' || path.startsWith('/proc/net/')) return 'proc-network';
    if (path === '/proc/self/mountinfo' || path === '/proc/mounts') return 'mounts';
    if (path.startsWith('/proc/')) return 'proc-other';
    if (path.startsWith('/etc/os-release') || path.startsWith('/usr/lib/os-release')) return 'os-release';
    return null;
  }
  function origin(context, returnAddress) {
    const module = Process.findModuleByAddress(returnAddress);
    let stack = [];
    try {
      stack = Thread.backtrace(context, Backtracer.ACCURATE)
        .slice(0, options.maxStack)
        .map(function (address) { return DebugSymbol.fromAddress(address).toString(); });
    } catch (_) {}
    return { module: module ? module.name : null, stack: stack };
  }
  function emit(event) {
    const category = event.path_category || event.fd_category || event.kind;
    if (options.categories.length && options.categories.indexOf(category) < 0) return;
    if (emitted >= options.maxEvents) {
      if (!dropped) { dropped = true; send({ kind: 'dropped', pid: Process.id, reason: 'event-cap', cap: options.maxEvents }); }
      return;
    }
    emitted += 1;
    event.timestamp_ms = Date.now();
    event.pid = Process.id;
    event.tid = Process.getCurrentThreadId();
    send(event);
  }
  function hook(name, callbacks) {
    const address = find(name);
    if (!address) return;
    const key = address.toString();
    // On glibc, open/open64 and several stat variants can be the same entry.
    // Recording one boundary event is both more accurate and less noisy.
    if (hookedAddresses.has(key)) return;
    hookedAddresses.add(key);
    Interceptor.attach(address, callbacks);
  }
  function fsHook(name, pathAt) {
    hook(name, {
      onEnter: function (args) {
        this.path = text(args[pathAt]);
        this.category = category(this.path);
        this.contextForEvent = this.context;
        this.returnAddressForEvent = this.returnAddress;
      },
      onLeave: function (result) {
        if (!this.category) return;
        const fd = result.toInt32();
        if (fd >= 0) trackedFds.set(fd, this.category);
        emit(Object.assign({ kind: 'filesystem', operation: name, path_category: this.category,
          success: fd >= 0, result_kind: fd >= 0 ? 'file-descriptor' : 'error', errno: this.errno },
          origin(this.contextForEvent, this.returnAddressForEvent)));
      }
    });
  }
  function simple(name, eventKind, extra) {
    hook(name, {
      onEnter: function () { this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; },
      onLeave: function (result) {
        emit(Object.assign({ kind: eventKind, operation: name, success: result.toInt32() >= 0,
          result_kind: result.toInt32() >= 0 ? 'success' : 'error', errno: this.errno }, extra || {},
          origin(this.contextForEvent, this.returnAddressForEvent)));
      }
    });
  }
  function gpuString(value) {
    // GPU strings are real hardware identifiers in hardware mode. Keep them
    // out of the default redacted diagnostic stream; an operator must opt in
    // explicitly when they need to compare API-visible results.
    if (!options.captureGpuValues) return 'redacted-gpu-string';
    const result = text(value);
    return result === null ? null : result.slice(0, 256);
  }
  function glStringName(value) {
    const names = { 0x1F00: 'vendor', 0x1F01: 'renderer', 0x1F02: 'version', 0x1F03: 'extensions' };
    return names[value] || ('enum-0x' + value.toString(16));
  }
  function eglStringName(value) {
    const names = { 0x3053: 'vendor', 0x3054: 'version', 0x3055: 'extensions', 0x308D: 'client-apis' };
    return names[value] || ('enum-0x' + value.toString(16));
  }
  function stringQuery(name, queryName) {
    hook(name, {
      onEnter: function (args) {
        this.query = args[queryName].toUInt32();
        this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress;
      },
      onLeave: function (result) {
        emit(Object.assign({ kind: 'graphics-api', operation: name,
          query: name === 'glGetString' ? glStringName(this.query) : eglStringName(this.query),
          success: !result.isNull(), result_kind: result.isNull() ? 'null' : 'gpu-string',
          value: gpuString(result) }, origin(this.contextForEvent, this.returnAddressForEvent)));
      }
    });
  }
  function cpuCount(name) {
    hook(name, {
      onEnter: function (args) {
        this.argument = args[0].toInt32(); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress;
      },
      onLeave: function (result) {
        const raw = result.toInt32();
        // glibc's Linux values: 83 = configured processors, 84 = online.
        const query = name === 'sysconf' ? ({83: 'processors-configured', 84: 'processors-online'}[this.argument] || ('selector-' + this.argument)) : name;
        emit(Object.assign({ kind: 'cpu-api', operation: name, query: query,
          success: raw >= 0, result_kind: raw >= 0 ? 'cpu-count' : 'error', value: raw >= 0 ? raw : null,
          errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent)));
      }
    });
  }
  function graphicsFunction(name, resultType) {
    hook(name, {
      onEnter: function () { this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; },
      onLeave: function (result) {
        let success = true;
        if (resultType === 'pointer') success = !result.isNull();
        if (resultType === 'status') success = result.toInt32() >= 0;
        emit(Object.assign({ kind: 'graphics-api', operation: name, success: success,
          result_kind: resultType === 'void' ? 'void' : (success ? resultType : 'error'),
          errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent)));
      }
    });
  }
  function install() {
    if (installed) return;
    installed = true;
    fsHook('open', 0); fsHook('open64', 0); fsHook('openat', 1); fsHook('openat64', 1);
    ['access', 'stat', 'lstat'].forEach(function (name) { fsHook(name, 0); });
    ['readlink'].forEach(function (name) { fsHook(name, 0); });
    fsHook('readlinkat', 1);
    hook('newfstatat', { onEnter: function (args) { this.path = text(args[1]); this.category = category(this.path); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { if (this.category) emit(Object.assign({ kind: 'filesystem', operation: 'newfstatat', path_category: this.category, success: result.toInt32() === 0, result_kind: result.toInt32() === 0 ? 'success' : 'error', errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    hook('close', { onEnter: function (args) { this.fd = args[0].toInt32(); }, onLeave: function () { trackedFds.delete(this.fd); } });
    hook('read', { onEnter: function (args) { this.fd = args[0].toInt32(); this.category = trackedFds.get(this.fd); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { if (this.category) emit(Object.assign({ kind: 'filesystem-read', operation: 'read', path_category: this.category, success: result.toInt32() >= 0, result_kind: result.toInt32() >= 0 ? 'bytes' : 'error', errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    ['gethostname', 'uname', 'sysinfo', 'getifaddrs'].forEach(function (name) { simple(name, 'host-api'); });
    cpuCount('sysconf'); cpuCount('get_nprocs'); cpuCount('get_nprocs_conf');
    stringQuery('glGetString', 0); stringQuery('eglQueryString', 1);
    graphicsFunction('drmGetVersion', 'pointer');
    graphicsFunction('drmGetDevice2', 'status');
    graphicsFunction('drmGetDevices2', 'status');
    graphicsFunction('vkGetPhysicalDeviceProperties', 'void');
    hook('getenv', { onEnter: function (args) { this.name = text(args[0]); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { const allowed = ['HOME','USER','LOGNAME','PATH','XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_CACHE_HOME','DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','DBUS_SESSION_BUS_ADDRESS']; if (allowed.indexOf(this.name) >= 0) emit(Object.assign({ kind: 'environment', operation: 'getenv', variable: this.name, success: !result.isNull(), result_kind: result.isNull() ? 'unset' : 'redacted-string' }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    hook('connect', { onEnter: function (args) { this.family = args[1].readU16(); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { emit(Object.assign({ kind: 'network', operation: 'connect', address_family: this.family === 2 ? 'inet' : (this.family === 10 ? 'inet6' : 'other'), success: result.toInt32() === 0, result_kind: result.toInt32() === 0 ? 'connected' : 'error', errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    hook('execve', { onEnter: function (args) { this.path = text(args[0]); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { emit(Object.assign({ kind: 'process', operation: 'execve', executable_category: category(this.path) || 'other', success: result.toInt32() === 0, result_kind: result.toInt32() === 0 ? 'replaced-process' : 'error', errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    hook('dlopen', { onEnter: function (args) { this.path = text(args[0]); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { if (this.path && (/dri|libGL|libEGL|libdrm|vulkan/i).test(this.path)) emit(Object.assign({ kind: 'library', operation: 'dlopen', library_category: 'graphics-or-drm', success: !result.isNull(), result_kind: result.isNull() ? 'error' : 'handle' }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    if (options.level === 'all') hook('ioctl', { onEnter: function (args) { this.fd = args[0].toInt32(); this.request = args[1].toString(); this.contextForEvent = this.context; this.returnAddressForEvent = this.returnAddress; }, onLeave: function (result) { emit(Object.assign({ kind: 'ioctl', operation: 'ioctl', fd_category: trackedFds.get(this.fd) || 'unclassified', request: this.request, success: result.toInt32() >= 0, result_kind: result.toInt32() >= 0 ? 'success' : 'error', errno: this.errno }, origin(this.contextForEvent, this.returnAddressForEvent))); } });
    send({ kind: 'observer-ready', pid: Process.id, level: options.level, max_events: options.maxEvents });
  }
  rpc.exports = { configure: function (config) { options = Object.assign(options, config || {}); install(); return { pid: Process.id, level: options.level }; } };
}());
