package com.filo.iotauth

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import android.util.Base64
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import java.security.KeyStore
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
// 【新增导入弹窗需要的包】
import android.app.AlertDialog
import android.text.InputType
import java.net.SocketTimeoutException

import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.Executor
import java.io.File
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    // ==========================================
    // JNI 接口声明
    // ==========================================
    external fun initDevice(uid: String, path: String): Boolean
    external fun generateRegisterPayload(pwd: String): String
    external fun processAuthChallenge(uid: String, pwd: String, dhpubSBase64: String, serverSigMBase64: String, timestamp: Long, nonceBase64: String, isBioSuccess: Boolean): String
    external fun processServerResponse(jsonResponse: String): Boolean
    external fun finalizeAuth(tagSBase64: String, serverSigTagBase64: String): Boolean
    external fun encryptCommand(plaintextCmd: String): String
    external fun decryptResponse(ciphertextB64: String): String
    // 注册 Keystore 回调到 C++ TEEKeyModule（由 JNI_OnLoad 时的 native 层持有）
    external fun registerKeystoreCallback(): Boolean

    // ==========================================
    // 类成员变量 (全局UI控件与状态)
    // ==========================================
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    // UI 控件
    private lateinit var etUid: EditText
    private lateinit var etPassword: EditText
    private lateinit var tvResult: TextView
    private lateinit var layoutLogin: LinearLayout
    private lateinit var layoutControl: LinearLayout

    // 设备控制状态
    private var doorStatus = false
    private var lightStatus = false
    private var acStatus = false
    private var acTemp = 24
    private var acMode = "cool"

    // 网络状态
    private val client = OkHttpClient()
    private var webSocket: WebSocket? = null

    // 性能统计
    private var registrationStartTime = 0L
    private var authStartTime = 0L
    private var challengeReceivedTime = 0L
    private var fingerPromptStartTime = 0L
    private var fingerWaitDuration = 0L

    // 动态获取的地址
    private var gatewayIp = ""
    private var httpRegisterUrl = ""
    private var wsAuthUrl = ""
    private var isDiscovering = true // 控制监听循环的开关

    // 定义当前操作状态，用于区分指纹验证后的回调逻辑
    enum class ActionType { NONE, REGISTER, AUTHENTICATE }
    private var currentAction = ActionType.NONE

    // 用于暂存 WebSocket 收到的挑战参数，等待指纹验证后使用
    private var pendingDhpubS = ""
    private var pendingServerSigM = ""
    private var pendingTimestamp: Long = 0L
    private var pendingNonce = ""

    // ==========================================
    // Kotlin 层的底座安全防线：ECDSA 验签
    // ==========================================
    @Suppress("unused")
    fun verifySignatureInJava(pkBase64: String, messageBase64: String, signatureBase64: String): Boolean {
        return try {
            val pkBytes = Base64.decode(pkBase64, Base64.DEFAULT)
            val keySpec = X509EncodedKeySpec(pkBytes)
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(keySpec)

            val messageBytes = Base64.decode(messageBase64, Base64.DEFAULT)
            val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)

            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(publicKey)
            signature.update(messageBytes)

            val isSuccess = signature.verify(signatureBytes)
            println("======> Kotlin 层验签结果: $isSuccess <======")
            isSuccess
        } catch (e: Exception) {
            println("======> Kotlin 层验签抛出异常: ${e.message} <======")
            e.printStackTrace()
            false
        }
    }

    // ==========================================
    // Android Keystore TEE 硬件密钥管理
    // ==========================================

    private val KEY_ALIAS = "iot_auth_device_key"
    private val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * 确保 AndroidKeyStore 中存在硬件支持的 HmacSHA256 密钥。
     * 若已存在则直接复用（幂等），不可导出，生命周期绑定设备。
     */
    private fun ensureKeystoreKey() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) return

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA256,
            ANDROID_KEYSTORE
        )
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
            )
                .setKeySize(256)
                .build()
        )
        keyGenerator.generateKey()
        println("======> TEE 设备密钥已生成并写入 AndroidKeyStore <======")
    }

    /**
     * 使用 AndroidKeyStore 中的硬件密钥执行 HMAC-SHA256。
     * 由 C++ TEEKeyModule 的 JNI 回调触发，data 为原始字节（Base64 编码后传入）。
     * 返回 HMAC 结果的 Base64 字符串。
     *
     * 此方法由 native-lib.cpp 通过 JNI 反调，标注 @Suppress("unused") 防止被混淆器删除。
     */
    @Suppress("unused")
    fun performKeystoreHmac(keyAlias: String, dataBase64: String): String {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val secretKey = keyStore.getKey(keyAlias, null)
                ?: throw IllegalStateException("Keystore key '$keyAlias' not found")

            val mac = Mac.getInstance("HmacSHA256")
            mac.init(secretKey)

            val data = Base64.decode(dataBase64, Base64.DEFAULT)
            val result = mac.doFinal(data)

            Base64.encodeToString(result, Base64.NO_WRAP).also {
                println("======> TEE HMAC 完成，输出长度: ${result.size} 字节 <======")
            }
        } catch (e: Exception) {
            println("======> TEE HMAC 失败: ${e.message} <======")
            e.printStackTrace()
            "" // 空字符串触发 C++ 侧降级到 PBKDF2
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        copyAssetsToInternalStorage()

        etUid = findViewById(R.id.etUid)
        etPassword = findViewById(R.id.etPassword)
        tvResult = findViewById(R.id.tvResult)

        layoutLogin = findViewById(R.id.layoutLogin)
        layoutControl = findViewById(R.id.layoutControl)

        val btnRegister = findViewById<Button>(R.id.btnRegister)
        val btnAuth = findViewById<Button>(R.id.btnAuth)
        val btnToggleDoor = findViewById<Button>(R.id.btnToggleDoor)
        val btnToggleLight = findViewById<Button>(R.id.btnToggleLight)
        val btnAcPower = findViewById<Button>(R.id.btnAcPower)
        val btnAcTempUp = findViewById<Button>(R.id.btnAcTempUp)
        val btnAcTempDown = findViewById<Button>(R.id.btnAcTempDown)
        val btnLogout = findViewById<Button>(R.id.btnLogout)
        val btnAcMode = findViewById<Button>(R.id.btnAcMode)

        // 退出登录逻辑
        btnLogout.setOnClickListener {
            webSocket?.close(1000, "User logged out")
            webSocket = null

            doorStatus = false
            lightStatus = false
            acStatus = false
            currentAction = ActionType.NONE

            layoutControl.visibility = View.GONE
            layoutLogin.visibility = View.VISIBLE

            tvResult.text = "🔴 已安全退出登录，加密连接已销毁。\n等待操作..."
        }

        // 初始化指纹 TEE 环境
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    fingerWaitDuration = System.currentTimeMillis() - fingerPromptStartTime
                    if (currentAction == ActionType.REGISTER) {
                        tvResult.text = "TEE 硬件指纹验证通过。\n正在生成底层注册载荷...\n"

                        val payloadGenStart = System.currentTimeMillis()
                        val pwd = etPassword.text.toString()
                        val payloadJson = generateRegisterPayload(pwd)
                        val payloadGenTime = System.currentTimeMillis() - payloadGenStart

                        if (payloadJson.startsWith("{\"error\"")) {
                            tvResult.append("\n底层执行异常: $payloadJson")
                            return
                        }
                        tvResult.append("\n载荷生成耗时: ${payloadGenTime}ms\n正在通过 HTTP 发送至网关...")
                        sendRegistrationRequest(payloadJson)

                    } else if (currentAction == ActionType.AUTHENTICATE) {
                        tvResult.append("\nTEE 硬件指纹验证通过。\n正在计算挑战响应...")
                        executeAuthResponse(true, etUid.text.toString(), etPassword.text.toString())
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (currentAction == ActionType.AUTHENTICATE) {
                        tvResult.append("\n指纹错误或取消验证(注入极大噪声)。\n模拟被黑客攻击...")
                        executeAuthResponse(false, etUid.text.toString(), etPassword.text.toString())
                    } else {
                        tvResult.text = "指纹验证终止: $errString"
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "指纹验证未通过，请重试", Toast.LENGTH_SHORT).show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("设备安全授权")
            .setSubtitle("请验证设备管理员指纹")
            .setNegativeButtonText("取消/模拟验证失败")
            .build()

        btnRegister.setOnClickListener {
            val uid = etUid.text.toString()
            if (uid.isEmpty()) return@setOnClickListener Toast.makeText(this, "UID 不能为空", Toast.LENGTH_SHORT).show()

            if (!initDeviceInstance(uid)) return@setOnClickListener

            registrationStartTime = System.currentTimeMillis()
            currentAction = ActionType.REGISTER
            tvResult.text = "正在请求注册...\n等待指纹授权..."
            fingerPromptStartTime = System.currentTimeMillis()
            biometricPrompt.authenticate(promptInfo)
        }

        btnAuth.setOnClickListener {
            val uid = etUid.text.toString()
            val pwd = etPassword.text.toString()
            if (uid.isEmpty() || pwd.isEmpty()) return@setOnClickListener Toast.makeText(this, "UID或密码为空", Toast.LENGTH_SHORT).show()

            if (!initDeviceInstance(uid)) return@setOnClickListener

            authStartTime = System.currentTimeMillis()
            currentAction = ActionType.AUTHENTICATE
            tvResult.text = "正在连接网关建立 WebSocket..."
            startWebSocketAuth(uid)
        }

        btnToggleDoor.setOnClickListener {
            doorStatus = !doorStatus
            sendSecureCommand("door", if (doorStatus) "unlock" else "lock")
        }

        btnToggleLight.setOnClickListener {
            lightStatus = !lightStatus
            sendSecureCommand("light", if (lightStatus) "turn_on" else "turn_off")
        }

        btnAcPower.setOnClickListener {
            acStatus = !acStatus
            sendSecureCommand("ac", "sync_state", mapOf("power" to acStatus, "mode" to acMode, "temp" to acTemp))
        }

        btnAcTempUp.setOnClickListener {
            if (acStatus && acTemp < 30) {
                acTemp++
                sendSecureCommand("ac", "sync_state", mapOf("power" to true, "mode" to acMode, "temp" to acTemp))
            }
        }

        btnAcTempDown.setOnClickListener {
            if (acStatus && acTemp > 16) {
                acTemp--
                sendSecureCommand("ac", "sync_state", mapOf("power" to true, "mode" to acMode, "temp" to acTemp))
            }
        }
        btnAcMode.setOnClickListener {
            if (!acStatus) {
                Toast.makeText(this, "请先打开空调电源", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            acMode = if (acMode == "cool") "heat" else "cool"
            sendSecureCommand("ac", "sync_state", mapOf("power" to true, "mode" to acMode, "temp" to acTemp))
            btnAcMode.text = if (acMode == "cool") "❄️ 切至制热" else "☀️ 切至制冷"
        }

        // 【关键点】：程序启动时开启发现
        startUdpDiscovery()
    }

    private fun copyAssetsToInternalStorage() {
        val destFolder = File(filesDir, "fingerprint_features")
        if (!destFolder.exists()) destFolder.mkdirs()

        try {
            val files = assets.list("fingerprint_features") ?: return
            for (filename in files) {
                val destFile = File(destFolder, filename)
                if (!destFile.exists()) {
                    assets.open("fingerprint_features/$filename").use { inStream ->
                        FileOutputStream(destFile).use { outStream ->
                            inStream.copyTo(outStream)
                        }
                    }
                }
            }
            println("======> 物理指纹特征库释放成功！ <======")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun initDeviceInstance(uid: String): Boolean {
        val storagePath = applicationContext.filesDir.absolutePath

        // 1. 确保 AndroidKeyStore 中存在硬件密钥（幂等）
        try {
            ensureKeystoreKey()
        } catch (e: Exception) {
            println("======> Keystore 密钥生成失败，将降级为 PBKDF2: ${e.message} <======")
        }

        // 2. 初始化 C++ User 对象
        val initSuccess = initDevice(uid, storagePath)
        if (!initSuccess) {
            tvResult.text = "C++ 引擎初始化失败，请检查 JNI 层。"
            return false
        }

        // 3. 将 Kotlin performKeystoreHmac 注册为 C++ TEEKeyModule 的回调
        //    C++ 侧会持有 JNIEnv + jobject 引用，后续 Enroll/Derive 时直接回调
        val callbackRegistered = registerKeystoreCallback()
        if (!callbackRegistered) {
            println("======> Keystore 回调注册失败，TEEKeyModule 将使用 PBKDF2 降级路径 <======")
        }

        return true
    }

    private fun sendRegistrationRequest(jsonPayload: String) {
        val requestBody = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaType())
        val request = Request.Builder().url(httpRegisterUrl).post(requestBody).build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread { tvResult.append("\n\n注册网络请求失败: ${e.message}") }
            }
            override fun onResponse(call: Call, response: Response) {
                val responseData = response.body?.string() ?: ""
                val totalRegTime = (System.currentTimeMillis() - registrationStartTime) - fingerWaitDuration
                runOnUiThread {
                    if (response.isSuccessful && processServerResponse(responseData)) {
                        tvResult.append("\n\n✅ 注册闭环完成！服务器公钥已安全落盘。\n总耗时: ${totalRegTime}ms")
                    } else {
                        tvResult.append("\n\n❌ 注册失败或底层处理异常: $responseData")
                    }
                }
            }
        })
    }

    private fun startWebSocketAuth(uid: String) {
        val request = Request.Builder().url(wsAuthUrl).build()

        webSocket = client.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                val authReq = JSONObject().apply {
                    put("type", "auth_request")
                    put("uid", uid)
                }
                webSocket.send(authReq.toString())
                runOnUiThread { tvResult.append("\n\n已发送 auth_request，等待挑战...") }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val json = JSONObject(text)
                when (json.getString("type")) {
                    "system_reset" -> {
                        runOnUiThread {
                            tvResult.append("\n\n⚠️ 收到网关广播：系统已重置！\n正在销毁本地安全连接并退回首页...")

                            this@MainActivity.webSocket?.close(1000, "Server Force Reset")
                            this@MainActivity.webSocket = null

                            doorStatus = false
                            lightStatus = false
                            acStatus = false
                            currentAction = ActionType.NONE

                            layoutControl.visibility = View.GONE
                            layoutLogin.visibility = View.VISIBLE

                            Toast.makeText(this@MainActivity, "网关数据库已清空，设备被强制下线", Toast.LENGTH_LONG).show()
                        }
                    }
                    "auth_challenge" -> {
                        challengeReceivedTime = System.currentTimeMillis()
                        val networkLatency = challengeReceivedTime - authStartTime
                        pendingDhpubS = json.getString("dhpubS")
                        pendingServerSigM = json.getString("serversigm")
                        pendingTimestamp = json.getLong("timestamp")
                        pendingNonce = json.getString("nonce")

                        runOnUiThread {
                            tvResult.append("\n收到挑战包 (网络延迟: ${networkLatency}ms)，唤起 TEE 验证...")
                            fingerPromptStartTime = System.currentTimeMillis()
                            biometricPrompt.authenticate(promptInfo)
                        }
                    }

                    "auth_confirmation" -> {
                        val success = json.getBoolean("success")
                        val totalAuthTime = (System.currentTimeMillis() - authStartTime) - fingerWaitDuration
                        runOnUiThread {
                            if (success) {
                                val tagS = json.getString("tagS")
                                val serverSigTag = json.getString("serversigtag")

                                val finalizeStart = System.currentTimeMillis()
                                val isFinalVerified = finalizeAuth(tagS, serverSigTag)
                                val finalizeTime = System.currentTimeMillis() - finalizeStart

                                if (isFinalVerified) {
                                    tvResult.append("\n\n✅ 双向认证成功！会话密钥协商完毕。\n总认证耗时: ${totalAuthTime}ms (最终验证: ${finalizeTime}ms)")
                                    layoutLogin.visibility = View.GONE
                                    layoutControl.visibility = View.VISIBLE
                                } else {
                                    tvResult.append("\n\n❌ 严重警告：网关签名伪造！可能遭遇中间人攻击。")
                                }
                            } else {
                                tvResult.append("\n\n❌ 认证被网关拒绝：密码错误或模糊提取失败。\n总耗时: ${totalAuthTime}ms")
                            }
                        }
                    }

                    "command_result" -> {
                        val payloadB64 = json.getString("payload")
                        val plaintextFeedback = decryptResponse(payloadB64)

                        runOnUiThread {
                            if (plaintextFeedback.isNotEmpty()) {
                                tvResult.append("\n✅ 收到网关加密回执: $plaintextFeedback")
                            } else {
                                tvResult.append("\n🛑 警报：解密网关回执失败！可能遭遇重放攻击或数据篡改。")
                            }
                        }
                    }
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                runOnUiThread { tvResult.append("\n\nWebSocket 异常中断: ${t.message}") }
            }
        })
    }

    private fun executeAuthResponse(isBioSuccess: Boolean, uid: String, pwd: String) {
        val responseGenStart = System.currentTimeMillis()
        val responseJsonStr = processAuthChallenge(uid, pwd, pendingDhpubS, pendingServerSigM, pendingTimestamp, pendingNonce, isBioSuccess)
        val responseGenTime = System.currentTimeMillis() - responseGenStart

        val responseJson = JSONObject(responseJsonStr).apply {
            put("type", "auth_response")
        }
        webSocket?.send(responseJson.toString())
        tvResult.append("\n响应生成耗时: ${responseGenTime}ms\n响应已发出，等待服务器鉴权...")
    }

    private fun sendSecureCommand(device: String, action: String, extraParams: Map<String, Any> = emptyMap()) {
        if (webSocket == null) {
            tvResult.append("\n❌ 错误：WebSocket连接已断开！")
            return
        }

        val cmdJson = JSONObject()
        cmdJson.put("device", device)
        cmdJson.put("action", action)
        for ((k, v) in extraParams) {
            cmdJson.put(k, v)
        }
        val plaintext = cmdJson.toString()

        val ciphertextB64 = encryptCommand(plaintext)
        if (ciphertextB64.isEmpty()) {
            tvResult.append("\n❌ 错误：底层加密引擎故障或未初始化！")
            return
        }

        val wsPayload = JSONObject()
        wsPayload.put("type", "secure_command")
        wsPayload.put("uid", etUid.text.toString().trim())
        wsPayload.put("command", ciphertextB64)

        tvResult.append("\n🔒 发送密文指令至网关: $plaintext")
        webSocket?.send(wsPayload.toString())
    }

    // ==========================================
    // 【核心修改】：自带 3 秒超时的 UDP 扫描
    // ==========================================
    private fun startUdpDiscovery() {
        thread {
            try {
                val socket = DatagramSocket(9999)
                socket.broadcast = true
                socket.soTimeout = 3000 // 【新增】设置 3 秒超时保命机制

                val buffer = ByteArray(1024)
                val packet = DatagramPacket(buffer, buffer.size)

                runOnUiThread {
                    tvResult.text = "🔍 正在局域网中寻找 IoT 网关，请确保设备在同一 Wi-Fi 下..."
                }

                while (isDiscovering) {
                    try {
                        socket.receive(packet) // 如果3秒没收到，会抛出 SocketTimeoutException
                        val message = String(packet.data, 0, packet.length)

                        if (message == "IOT_AUTH_GATEWAY_v1") {
                            gatewayIp = packet.address.hostAddress ?: continue
                            isDiscovering = false
                            socket.close()

                            httpRegisterUrl = "http://$gatewayIp:8081/api/register"
                            wsAuthUrl = "ws://$gatewayIp:8081/ws/auth"

                            runOnUiThread {
                                tvResult.text = "✅ 自动配网成功！\n发现安全网关: $gatewayIp\n系统已就绪，请进行注册或认证。"
                            }
                        }
                    } catch (e: SocketTimeoutException) {
                        // 【触发保命后门】：3秒都没监听到，极大概率遭遇了校园网的 AP 隔离
                        isDiscovering = false
                        socket.close()

                        runOnUiThread {
                            tvResult.text = "⚠️ 自动发现超时 (可能处于校园网隔离环境)。\n请手动输入网关 IP 继续。"
                            showManualIpDialog()
                        }
                    }
                }
            } catch (e: Exception) {
                e.printStackTrace()
                runOnUiThread { tvResult.append("\n❌ 局域网扫描异常: ${e.message}") }
            }
        }
    }

    // ==========================================
    // 【新增】：手动输入 IP 的退路对话框
    // ==========================================
    private fun showManualIpDialog() {
        val builder = AlertDialog.Builder(this)
        builder.setTitle("局域网发现失败")
        builder.setMessage("当前网络（如校园网）可能屏蔽了UDP广播，请输入网关电脑的IP地址 (例如 192.168.x.x)：")

        val input = EditText(this)
        input.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
        input.setPadding(50, 20, 50, 20)
        builder.setView(input)

        builder.setPositiveButton("确定") { dialog, _ ->
            val ip = input.text.toString().trim()
            if (ip.isNotEmpty()) {
                gatewayIp = ip
                httpRegisterUrl = "http://$gatewayIp:8081/api/register"
                wsAuthUrl = "ws://$gatewayIp:8081/ws/auth"
                tvResult.text = "✅ 手动配网成功！\n网关已设为: $gatewayIp\n系统已就绪，请进行注册或认证。"
            } else {
                Toast.makeText(this, "IP 不能为空，请重试", Toast.LENGTH_SHORT).show()
                showManualIpDialog() // 如果没输，再次弹窗
            }
            dialog.dismiss()
        }

        builder.setCancelable(false) // 强制必须输入，点击外部不消失
        builder.show()
    }

    companion object {
        init {
            System.loadLibrary("iotauthclient")
        }
    }
}