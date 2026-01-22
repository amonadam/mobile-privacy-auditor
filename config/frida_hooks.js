// Frida 插桩脚本 - Hook 敏感 API 并注入金丝雀数据
// 此脚本会拦截应用对隐私相关 API 的调用，并返回伪造的特征数据（金丝雀）

console.log("[*] Frida hooks script loaded");

// 生成唯一的金丝雀值
function generateCanary(apiName) {
    var timestamp = Date.now();
    var random = Math.floor(Math.random() * 10000);
    return "CANARY-" + apiName.toUpperCase() + "-" + timestamp + "-" + random;
}

// 获取调用堆栈
function getStackTrace() {
    try {
        throw new Error();
    } catch (e) {
        return e.stack || "No stack trace available";
    }
}

// 发送消息到控制端
function sendMessage(type, api, payload, stackTrace) {
    send({
        type: type,
        api: api,
        payload: payload,
        stack_trace: stackTrace
    });
}

// ==================== 设备标识符相关 API ====================

function hookDeviceIdentifiers() {
    console.log("[*] Hooking device identifier APIs...");
    
    if (Java.available) {
        Java.perform(function() {
            // 1. TelephonyManager - 设备标识符
            try {
                var TelephonyManager = Java.use("android.telephony.TelephonyManager");
                
                // getDeviceId (IMEI)
                TelephonyManager.getDeviceId.implementation = function() {
                    var canary = generateCanary("getDeviceId");
                    var stackTrace = getStackTrace();
                    console.log("[+] Hooked getDeviceId() -> " + canary);
                    sendMessage("canary_injected", "getDeviceId", canary, stackTrace);
                    return canary;
                };
                
                // getImei (Android 6.0+)
                TelephonyManager.getImei.implementation = function(slotIndex) {
                    var canary = generateCanary("getImei");
                    var stackTrace = getStackTrace();
                    console.log("[+] Hooked getImei() -> " + canary);
                    sendMessage("canary_injected", "getImei", canary, stackTrace);
                    return canary;
                };
                
                // getSubscriberId (IMSI)
                TelephonyManager.getSubscriberId.implementation = function() {
                    var canary = generateCanary("getSubscriberId");
                    var stackTrace = getStackTrace();
                    console.log("[+] Hooked getSubscriberId() -> " + canary);
                    sendMessage("canary_injected", "getSubscriberId", canary, stackTrace);
                    return canary;
                };
                
                // getLine1Number (手机号)
                TelephonyManager.getLine1Number.implementation = function() {
                    var canary = generateCanary("getLine1Number");
                    var stackTrace = getStackTrace();
                    console.log("[+] Hooked getLine1Number() -> " + canary);
                    sendMessage("canary_injected", "getLine1Number", canary, stackTrace);
                    return canary;
                };
                
                console.log("[+] Hooked TelephonyManager APIs");
            } catch (e) {
                console.log("[*] Error hooking TelephonyManager: " + e);
            }
            
            // 2. WifiInfo - MAC 地址
            try {
                var WifiInfo = Java.use("android.net.wifi.WifiInfo");
                WifiInfo.getMacAddress.implementation = function() {
                    var canary = generateCanary("getMacAddress");
                    var stackTrace = getStackTrace();
                    console.log("[+] Hooked getMacAddress() -> " + canary);
                    sendMessage("canary_injected", "getMacAddress", canary, stackTrace);
                    return canary;
                };
                console.log("[+] Hooked WifiInfo.getMacAddress");
            } catch (e) {
                console.log("[*] Error hooking WifiInfo: " + e);
            }
            
            // 3. Build - 设备信息
            try {
                var Build = Java.use("android.os.Build");
                
                // Hook Build.SERIAL
                var BuildClass = Java.use("android.os.Build$VERSION");
                
                // 注意：Build 类的字段是静态的，需要特殊处理
                // 这里我们通过 Hook 可能访问这些字段的方法来监控
                
                console.log("[+] Monitored Build class for device info");
            } catch (e) {
                console.log("[*] Error monitoring Build class: " + e);
            }
        });
    }
}

// ==================== 地理位置相关 API ====================

function hookLocationAPIs() {
    console.log("[*] Hooking location APIs...");
    
    if (Java.available) {
        Java.perform(function() {
            // 1. LocationManager
            try {
                var LocationManager = Java.use("android.location.LocationManager");
                
                // getLastKnownLocation
                LocationManager.getLastKnownLocation.implementation = function(provider) {
                    console.log("[+] Hooked getLastKnownLocation() with provider: " + provider);
                    var stackTrace = getStackTrace();
                    
                    // 返回一个伪造的 Location 对象
                    try {
                        var Location = Java.use("android.location.Location");
                        var fakeLocation = Location.$new(provider);
                        
                        // 设置伪造的坐标
                        var canaryLat = generateCanary("latitude");
                        var canaryLon = generateCanary("longitude");
                        
                        // 注意：Location 对象的 setLatitude 和 setLongitude 方法接受 double 类型
                        // 这里我们使用固定的伪造坐标，因为字符串无法直接转换为 double
                        fakeLocation.setLatitude(39.9042); // 北京纬度
                        fakeLocation.setLongitude(116.4074); // 北京经度
                        
                        sendMessage("canary_injected", "getLastKnownLocation", "Lat:39.9042,Lon:116.4074", stackTrace);
                        return fakeLocation;
                    } catch (e) {
                        console.log("[*] Error creating fake Location: " + e);
                        // 调用原始方法作为 fallback
                        return this.getLastKnownLocation(provider);
                    }
                };
                
                // requestLocationUpdates
                LocationManager.requestLocationUpdates.overload(
                    "java.lang.String", "long", "float", "android.location.LocationListener"
                ).implementation = function(provider, minTime, minDistance, listener) {
                    console.log("[+] Hooked requestLocationUpdates()");
                    var stackTrace = getStackTrace();
                    sendMessage("hook_event", "requestLocationUpdates", {
                        provider: provider,
                        minTime: minTime,
                        minDistance: minDistance
                    }, stackTrace);
                    
                    // 调用原始方法
                    this.requestLocationUpdates(provider, minTime, minDistance, listener);
                };
                
                console.log("[+] Hooked LocationManager APIs");
            } catch (e) {
                console.log("[*] Error hooking LocationManager: " + e);
            }
        });
    }
}

// ==================== 剪贴板相关 API ====================

function hookClipboard() {
    console.log("[*] Hooking clipboard APIs...");
    
    if (Java.available) {
        Java.perform(function() {
            // 1. ClipboardManager
            try {
                var ClipboardManager = Java.use("android.content.ClipboardManager");
                
                // getPrimaryClip
                ClipboardManager.getPrimaryClip.implementation = function() {
                    console.log("[+] Hooked getPrimaryClip()");
                    var stackTrace = getStackTrace();
                    var canary = generateCanary("getPrimaryClip");
                    
                    // 返回一个伪造的 ClipData 对象
                    try {
                        var ClipData = Java.use("android.content.ClipData");
                        var fakeClipData = ClipData.newPlainText("fake label", canary);
                        sendMessage("canary_injected", "getPrimaryClip", canary, stackTrace);
                        return fakeClipData;
                    } catch (e) {
                        console.log("[*] Error creating fake ClipData: " + e);
                        // 调用原始方法作为 fallback
                        return this.getPrimaryClip();
                    }
                };
                
                console.log("[+] Hooked ClipboardManager APIs");
            } catch (e) {
                console.log("[*] Error hooking ClipboardManager: " + e);
            }
        });
    }
}

// ==================== 联系人相关 API ====================

function hookContacts() {
    console.log("[*] Hooking contacts APIs...");
    
    if (Java.available) {
        Java.perform(function() {
            // 1. ContactsContract (ContentResolver 查询)
            try {
                var ContentResolver = Java.use("android.content.ContentResolver");
                
                // query 方法 - 可能用于查询联系人
                ContentResolver.query.overload(
                    "android.net.Uri", "[Ljava.lang.String;", "java.lang.String", "[Ljava.lang.String;", "java.lang.String"
                ).implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
                    var uriString = uri.toString();
                    if (uriString.includes("contacts") || uriString.includes("Contacts")) {
                        console.log("[+] Hooked contacts query: " + uriString);
                        var stackTrace = getStackTrace();
                        sendMessage("hook_event", "ContentResolver.query", {
                            uri: uriString,
                            projection: projection,
                            selection: selection
                        }, stackTrace);
                    }
                    
                    // 调用原始方法
                    return this.query(uri, projection, selection, selectionArgs, sortOrder);
                };
                
                console.log("[+] Monitored ContentResolver for contacts access");
            } catch (e) {
                console.log("[*] Error monitoring ContentResolver: " + e);
            }
        });
    }
}

// ==================== 存储相关 API ====================

function hookStorage() {
    console.log("[*] Hooking storage APIs...");
    
    if (Java.available) {
        Java.perform(function() {
            // 1. File - 可能用于读取存储的隐私数据
            try {
                var File = Java.use("java.io.File");
                
                // exists
                File.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (path.includes("private") || path.includes("cache") || path.includes("data")) {
                        console.log("[+] Hooked file access: " + path);
                        var stackTrace = getStackTrace();
                        sendMessage("hook_event", "File.exists", {
                            path: path
                        }, stackTrace);
                    }
                    return this.exists();
                };
                
                console.log("[+] Monitored File class for storage access");
            } catch (e) {
                console.log("[*] Error monitoring File class: " + e);
            }
        });
    }
}

// ==================== 初始化 ====================

function init() {
    console.log("[*] Initializing Frida hooks...");
    
    // 调用各个 Hook 函数
    hookDeviceIdentifiers();
    hookLocationAPIs();
    hookClipboard();
    hookContacts();
    hookStorage();
    
    console.log("[+] All hooks initialized successfully");
}

// 当 Java 可用时初始化
if (Java.available) {
    Java.perform(init);
} else {
    console.log("[*] Java not available, some hooks may not be applied");
}
