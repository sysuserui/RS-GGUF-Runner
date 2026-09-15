package com.rs.ggufrunner

import android.app.ActivityManager
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MailOutline
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.fromHtml
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.lifecycle.lifecycleScope
import dev.ffmpegkit.llama.Llama
import dev.ffmpegkit.llama.LlamaConfig
import dev.ffmpegkit.llama.LlamaModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.intellij.markdown.flavours.gfm.GFMFlavourDescriptor
import org.intellij.markdown.html.HtmlGenerator
import org.intellij.markdown.parser.CancellationToken
import org.intellij.markdown.parser.MarkdownParser
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

// ---------- Data ----------

data class ModelEntry(
    val file: File,
    val name: String = file.name,
    val sizeBytes: Long = file.length(),
    val lastModified: Long = file.lastModified()
) {
    val sizeMb: Long get() = sizeBytes / (1024L * 1024L)
}

data class ChatMessage(
    val id: String = UUID.randomUUID().toString(),
    val isUser: Boolean,
    val text: String,
    val timestamp: Long = System.currentTimeMillis()
)

enum class ReportReason { OFFENSIVE, HARMFUL, HATE, MISLEADING, OTHER }

data class ReportEntry(
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val reason: ReportReason,
    val comment: String,
    val aiResponseText: String,
    val modelName: String?
)

data class ChatSession(
    val id: String = UUID.randomUUID().toString(),
    var title: String = "",
    val messages: SnapshotStateList<ChatMessage> = mutableStateListOf(),
    val createdAt: Long = System.currentTimeMillis()
)

private enum class Screen { MODELS, CHAT, SETTINGS }

private object AppScope {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
}

private object CryptoManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "rs_gguf_runner_data_key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH_BITS = 128

    private fun getOrCreateKey(): java.security.Key {
        val keyStore = java.security.KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        keyStore.getKey(KEY_ALIAS, null)?.let { return it }

        return try {
            generateKey(useStrongBox = true)
        } catch (e: Exception) {
            generateKey(useStrongBox = false)
        }
    }

    private fun generateKey(useStrongBox: Boolean): java.security.Key {
        val keyGenerator = javax.crypto.KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    fun encrypt(plainBytes: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance(TRANSFORMATION)
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        val cipherBytes = cipher.doFinal(plainBytes)
        return iv + cipherBytes
    }

    fun decrypt(combined: ByteArray): ByteArray {
        require(combined.size > GCM_IV_LENGTH) { "Encrypted data too short to contain an IV" }
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val cipherBytes = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
        val cipher = javax.crypto.Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            getOrCreateKey(),
            javax.crypto.spec.GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        )
        return cipher.doFinal(cipherBytes)
    }
}

private enum class AppLanguage { EN, HI }
private enum class ThemeMode { LIGHT, DARK, SYSTEM }

class MainActivity : ComponentActivity() {

    private lateinit var modelsDir: File
    private var loadedModel: LlamaModel? = null
    private var generationJob: Job? = null

    private val models = mutableStateListOf<ModelEntry>()
    private val activeModelPath = mutableStateOf<String?>(null)
    private val isModelBusy = mutableStateOf(false)
    private val statusMessage = mutableStateOf("")

    private val threads = mutableIntStateOf(2)
    private val contextSize = mutableIntStateOf(1024)
    private val maxTokens = mutableIntStateOf(150)

    private val isGenerating = mutableStateOf(false)
    private val isNativeCallActive = mutableStateOf(false)
    private val isStopping = mutableStateOf(false)
    private val lastStats = mutableStateOf("")

    private val chatSessions = mutableStateListOf<ChatSession>()
    private val currentSessionId = mutableStateOf<String?>(null)
    private val pendingRiskyLoad = mutableStateOf<Pair<ModelEntry, String>?>(null)

    private val reports = mutableStateListOf<ReportEntry>()
    private val pendingReport = mutableStateOf<ChatMessage?>(null)
    private val submittedReport = mutableStateOf<ReportEntry?>(null)

    private val appLanguage = mutableStateOf(AppLanguage.EN)
    private val themeMode = mutableStateOf(ThemeMode.SYSTEM)

    private lateinit var safPickerLauncher: ActivityResultLauncher<Array<String>>

    private fun tr(en: String, hi: String): String = if (appLanguage.value == AppLanguage.HI) hi else en

    private fun baseStorageDir(): File = noBackupFilesDir ?: filesDir

    private fun migrateLegacyStorageIfNeeded() {
        val oldBase = filesDir
        val newBase = baseStorageDir()
        if (oldBase.absolutePath == newBase.absolutePath) return

        try {
            val oldModels = File(oldBase, "models")
            val newModels = File(newBase, "models")
            if (oldModels.exists() && oldModels.isDirectory) {
                newModels.mkdirs()
                oldModels.listFiles()?.forEach { f ->
                    val dest = File(newModels, f.name)
                    if (!dest.exists()) {
                        if (f.copyTo(dest, overwrite = false).exists()) f.delete()
                    }
                }
                oldModels.delete()
            }

            listOf("chat_history.json", "reports.json").forEach { name ->
                val oldFile = File(oldBase, name)
                val newFile = File(newBase, name)
                if (oldFile.exists() && !newFile.exists()) {
                    oldFile.copyTo(newFile, overwrite = false)
                    oldFile.delete()
                }
            }
        } catch (_: Exception) { }
    }

    // True once initial local data (chat history, reports, model list) has finished
    // loading. installSplashScreen()'s keep-on-screen condition below reads this, so the
    // splash icon stays visible through that brief startup work instead of the app
    // flashing an empty screen for a moment before content is ready.
    private var isInitialDataReady = false

    override fun onCreate(savedInstanceState: Bundle?) {
        val splashScreen = installSplashScreen()
        super.onCreate(savedInstanceState)
        splashScreen.setKeepOnScreenCondition { !isInitialDataReady }
        enableEdgeToEdge()

        migrateLegacyStorageIfNeeded()
        modelsDir = File(baseStorageDir(), "models").apply { mkdirs() }
        loadPreferences()
        refreshModelList()
        loadChatHistory()
        loadReports()
        if (chatSessions.isEmpty()) {
            val fresh = ChatSession()
            chatSessions.add(fresh)
            currentSessionId.value = fresh.id
        }
        isInitialDataReady = true

        safPickerLauncher = registerForActivityResult(
            ActivityResultContracts.OpenDocument()
        ) { uri: Uri? -> if (uri != null) importModelFromUri(uri) }

        setContent {
            val systemDark = isSystemInDarkTheme()
            val darkTheme = when (themeMode.value) {
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
                ThemeMode.SYSTEM -> systemDark
            }
            MaterialTheme(colorScheme = if (darkTheme) darkColorScheme() else lightColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) { AppRoot() }
            }
        }
    }

    private fun prefs() = getSharedPreferences("app_prefs", Context.MODE_PRIVATE)

    private fun loadPreferences() {
        val p = prefs()
        appLanguage.value = if (p.getString("lang", "en") == "hi") AppLanguage.HI else AppLanguage.EN
        themeMode.value = when (p.getString("theme", "system")) {
            "light" -> ThemeMode.LIGHT
            "dark" -> ThemeMode.DARK
            else -> ThemeMode.SYSTEM
        }
    }

    private fun setLanguage(l: AppLanguage) {
        appLanguage.value = l
        prefs().edit().putString("lang", if (l == AppLanguage.HI) "hi" else "en").apply()
    }

    private fun setThemeMode(t: ThemeMode) {
        themeMode.value = t
        prefs().edit().putString("theme", when (t) {
            ThemeMode.LIGHT -> "light"; ThemeMode.DARK -> "dark"; ThemeMode.SYSTEM -> "system"
        }).apply()
    }

    private data class DeviceMemory(val totalBytes: Long, val availableBytes: Long, val isLowMemory: Boolean)

    private fun readDeviceMemory(): DeviceMemory {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        return DeviceMemory(info.totalMem, info.availMem, info.lowMemory)
    }

    private fun estimateRequiredBytes(modelBytes: Long, ctx: Int): Long {
        val approxKvCacheBytes = ctx.toLong() * 200_000L
        val computeBuffers = 180L * 1024L * 1024L
        return (modelBytes * 1.10).toLong() + approxKvCacheBytes + computeBuffers
    }

    private fun canFitInMemory(modelBytes: Long, ctx: Int): Pair<Boolean, String> {
        val mem = readDeviceMemory()
        val required = estimateRequiredBytes(modelBytes, ctx)
        val safetyMargin = 250L * 1024L * 1024L
        val ok = mem.availableBytes > required + safetyMargin && !mem.isLowMemory
        val msg = if (ok) "" else buildString {
            append(tr(
                "Approximate RAM requirement: ~${required / (1024 * 1024)} MB (actual usage may be higher)\n",
                "अनुमानित RAM ज़रूरत: ~${required / (1024 * 1024)} MB (असली उपयोग इससे ज़्यादा हो सकता है)\n"
            ))
            append(tr("Available: ${mem.availableBytes / (1024 * 1024)} MB\n\n", "उपलब्ध: ${mem.availableBytes / (1024 * 1024)} MB\n\n"))
            append(tr("Recommendations:\n", "सुझाव:\n"))
            append(tr("- Close other apps to free RAM\n", "- दूसरी ऐप्स बंद करके RAM फ्री करें\n"))
            if (ctx > 512) append(tr(
                "- Lower Context size in Settings (currently $ctx)\n",
                "- सेटिंग्स में कॉन्टेक्स्ट साइज़ घटाएँ (अभी $ctx)\n"
            ))
            append(tr("- Or choose a smaller/more quantized model\n\n", "- या एक छोटा/ज़्यादा-क्वांटाइज़्ड मॉडल चुनें\n\n"))
            append(tr("You can still try loading it, but it may crash.", "फिर भी लोड करने की कोशिश की जा सकती है, पर क्रैश का जोखिम है।"))
        }
        return ok to msg
    }

    private fun isValidGgufMagic(bytes: ByteArray): Boolean =
        bytes.size >= 4 && bytes[0] == 'G'.code.toByte() && bytes[1] == 'G'.code.toByte() &&
                bytes[2] == 'U'.code.toByte() && bytes[3] == 'F'.code.toByte()

    private fun sanitizedUniqueGgufName(rawName: String): String {
        val base = rawName.substringBeforeLast('.', rawName)
            .replace(Regex("[^A-Za-z0-9._-]"), "_")
            .take(80)
            .ifBlank { "model" }
        var candidate = "$base.gguf"
        var counter = 1
        while (File(modelsDir, candidate).exists()) {
            candidate = "$base ($counter).gguf"
            counter++
        }
        return candidate
    }

    private fun refreshModelList() {
        models.clear()
        modelsDir.listFiles { f -> f.isFile && f.name.endsWith(".gguf", ignoreCase = true) }
            ?.sortedByDescending { it.lastModified() }
            ?.forEach { models.add(ModelEntry(it)) }
    }

    private fun queryDisplayName(uri: Uri): String? {
        var name: String? = null
        val cursor: Cursor? = contentResolver.query(uri, null, null, null, null)
        cursor?.use {
            val idx = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && it.moveToFirst()) name = it.getString(idx)
        }
        return name
    }

    private fun importModelFromUri(uri: Uri) {
        isModelBusy.value = true
        statusMessage.value = tr("Checking selected file...", "फ़ाइल जाँची जा रही है...")
        lifecycleScope.launch {
            var target: File? = null
            try {
                val displayName = withContext(Dispatchers.IO) { queryDisplayName(uri) }
                    ?: "model_${System.currentTimeMillis()}"

                withContext(Dispatchers.IO) {
                    val incoming = contentResolver.openFileDescriptor(uri, "r")?.use { it.statSize } ?: -1L
                    val requiredFree = incoming * 2
                    if (incoming > 0 && requiredFree > modelsDir.usableSpace) {
                        throw IllegalStateException(tr(
                            "Not enough storage - need ${requiredFree / (1024 * 1024)} MB free (2x the model's ${incoming / (1024 * 1024)} MB) to keep the device from filling up",
                            "स्टोरेज कम है - ${requiredFree / (1024 * 1024)} MB खाली जगह चाहिए (मॉडल के ${incoming / (1024 * 1024)} MB का 2 गुना), ताकि फ़ोन फुल न हो"
                        ))
                    }
                    contentResolver.openInputStream(uri).use { rawInput ->
                        requireNotNull(rawInput) { tr("Could not open file", "फ़ाइल खुल नहीं पाई") }
                        val buffered = rawInput.buffered(8)
                        buffered.mark(8)
                        val header = ByteArray(4)
                        val readCount = buffered.read(header)
                        if (readCount < 4 || !isValidGgufMagic(header)) {
                            throw IllegalArgumentException(tr(
                                "This is not a valid GGUF file (wrong file type).",
                                "यह एक मान्य GGUF फ़ाइल नहीं है (गलत फ़ाइल टाइप हो सकती है)।"
                            ))
                        }
                        buffered.reset()
                        val safeName = sanitizedUniqueGgufName(displayName)
                        val f = File(modelsDir, safeName)
                        target = f
                        f.outputStream().use { output -> buffered.copyTo(output) }
                    }
                }
                statusMessage.value = tr("Model added: ${target?.name}", "मॉडल जोड़ा गया: ${target?.name}")
                refreshModelList()
            } catch (e: Exception) {
                target?.let { if (it.exists()) it.delete() }
                statusMessage.value = tr("Import failed: ${e.message}", "इंपोर्ट असफल हुआ: ${e.message}")
            } finally {
                isModelBusy.value = false
            }
        }
    }

    private fun selectActiveModel(entry: ModelEntry) {
        if (isNativeCallActive.value) {
            statusMessage.value = tr("Model is generating a reply - please wait.", "मॉडल अभी जवाब बना रहा है - पहले पूरा होने दें।")
            return
        }
        if (activeModelPath.value == entry.file.absolutePath) return

        val (fits, reason) = canFitInMemory(entry.sizeBytes, contextSize.intValue)
        if (!fits) {
            pendingRiskyLoad.value = entry to reason
            return
        }
        loadModelInternal(entry)
    }

    private fun loadModelInternal(entry: ModelEntry) {
        isModelBusy.value = true
        statusMessage.value = tr("Loading ${entry.name}...", "${entry.name} लोड हो रहा है...")
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.Default) {
                    unloadActiveModelBlocking()
                    loadedModel = Llama.loadModel(
                        modelPath = entry.file.absolutePath,
                        config = LlamaConfig(contextSize = contextSize.intValue, threads = threads.intValue)
                    )
                }
                activeModelPath.value = entry.file.absolutePath
                lastStats.value = ""
                statusMessage.value = tr("${entry.name} ready", "${entry.name} तैयार है")
            } catch (e: OutOfMemoryError) {
                unloadActiveModelSilently()
                statusMessage.value = tr(
                    "Ran out of RAM - model not loaded. Try a smaller model or lower context.",
                    "RAM कम पड़ गई - मॉडल लोड नहीं हुआ। छोटा मॉडल या कम कॉन्टेक्स्ट आज़माएँ।"
                )
            } catch (e: Exception) {
                unloadActiveModelSilently()
                statusMessage.value = tr("Load failed: ${e.message}", "लोड असफल हुआ: ${e.message}")
            } finally {
                isModelBusy.value = false
            }
        }
    }

    private fun unloadActiveModelBlocking() {
        loadedModel?.let { m -> try { Llama.releaseModel(m) } catch (_: Exception) { } }
        loadedModel = null
    }

    private fun unloadActiveModelSilently() {
        unloadActiveModelBlocking()
        activeModelPath.value = null
    }

    private fun unloadActiveModel() {
        if (isNativeCallActive.value) {
            statusMessage.value = tr("Model is generating a reply - please wait.", "मॉडल अभी जवाब बना रहा है - पहले पूरा होने दें।")
            return
        }
        isModelBusy.value = true
        lifecycleScope.launch {
            withContext(Dispatchers.Default) { unloadActiveModelBlocking() }
            activeModelPath.value = null
            statusMessage.value = tr("Model unloaded (RAM free)", "मॉडल अनलोड हो गया (RAM फ्री)")
            isModelBusy.value = false
        }
    }

    private fun deleteModel(entry: ModelEntry) {
        if (activeModelPath.value == entry.file.absolutePath && isNativeCallActive.value) {
            statusMessage.value = tr("This model is generating a reply - please wait.", "यह मॉडल अभी जवाब बना रहा है - पहले पूरा होने दें।")
            return
        }
        lifecycleScope.launch {
            if (activeModelPath.value == entry.file.absolutePath) {
                isModelBusy.value = true
                withContext(Dispatchers.Default) { unloadActiveModelBlocking() }
                activeModelPath.value = null
                isModelBusy.value = false
            }
            val deleted = withContext(Dispatchers.IO) { entry.file.delete() }
            statusMessage.value = if (deleted) tr("Deleted ${entry.name}", "${entry.name} डिलीट हो गया")
            else tr("Delete failed: ${entry.name}", "डिलीट असफल हुआ: ${entry.name}")
            refreshModelList()
        }
    }

    private fun clearAllUserData() {
        if (isNativeCallActive.value) {
            statusMessage.value = tr("Model is generating a reply - please wait.", "मॉडल अभी जवाब बना रहा है - पहले पूरा होने दें।")
            return
        }
        isModelBusy.value = true
        lifecycleScope.launch {
            withContext(Dispatchers.Default) { unloadActiveModelBlocking() }
            activeModelPath.value = null

            withContext(Dispatchers.IO) {
                modelsDir.listFiles()?.forEach { it.delete() }
                historyFile().let { if (it.exists()) it.delete() }
                reportsFile().let { if (it.exists()) it.delete() }
            }

            refreshModelList()
            chatSessions.clear()
            reports.clear()
            val fresh = ChatSession()
            chatSessions.add(fresh)
            currentSessionId.value = fresh.id
            lastStats.value = ""

            isModelBusy.value = false
            statusMessage.value = tr("All local data deleted.", "सारा लोकल डेटा डिलीट हो गया।")
        }
    }

    private fun currentSession(): ChatSession {
        val id = currentSessionId.value
        chatSessions.find { it.id == id }?.let { return it }
        val fresh = ChatSession()
        chatSessions.add(0, fresh)
        currentSessionId.value = fresh.id
        return fresh
    }

    private fun startNewChat() {
        if (isNativeCallActive.value) {
            statusMessage.value = tr("Please wait for the current response to finish.", "पहले मौजूदा रिस्पॉन्स पूरा होने दें।")
            return
        }
        val fresh = ChatSession()
        chatSessions.add(0, fresh)
        currentSessionId.value = fresh.id
        lastStats.value = ""
    }

    private fun switchToSession(id: String) {
        if (isNativeCallActive.value) {
            statusMessage.value = tr("Please wait for the current response to finish.", "पहले मौजूदा रिस्पॉन्स पूरा होने दें।")
            return
        }
        currentSessionId.value = id
        lastStats.value = ""
    }

    private fun renameSession(id: String, newTitle: String) {
        chatSessions.find { it.id == id }?.title = newTitle.trim()
        persistChatHistory()
    }

    private fun deleteSession(id: String) {
        if (currentSessionId.value == id && isNativeCallActive.value) {
            statusMessage.value = tr("This chat is active - please wait for the response to finish.", "यह चैट अभी एक्टिव है - पहले रिस्पॉन्स पूरा होने दें।")
            return
        }
        chatSessions.removeAll { it.id == id }
        if (currentSessionId.value == id) {
            currentSessionId.value = chatSessions.firstOrNull()?.id
            if (chatSessions.isEmpty()) startNewChat()
        }
        persistChatHistory()
    }

    private fun clearCurrentChat() {
        if (isNativeCallActive.value) {
            statusMessage.value = tr("Please wait for the current response to finish.", "पहले मौजूदा रिस्पॉन्स पूरा होने दें।")
            return
        }
        currentSession().messages.clear()
        lastStats.value = ""
        persistChatHistory()
    }

    private fun historyFile() = File(baseStorageDir(), "chat_history.json")

    private fun buildHistoryJson(): String {
        val arr = JSONArray()
        chatSessions.forEach { session ->
            val msgArr = JSONArray()
            session.messages.forEach { m ->
                msgArr.put(JSONObject().apply {
                    put("id", m.id); put("isUser", m.isUser); put("text", m.text); put("timestamp", m.timestamp)
                })
            }
            arr.put(JSONObject().apply {
                put("id", session.id); put("title", session.title)
                put("createdAt", session.createdAt); put("messages", msgArr)
            })
        }
        return arr.toString()
    }

    private fun persistChatHistory() {
        lifecycleScope.launch(Dispatchers.IO) {
            atomicWriteEncryptedText(historyFile(), buildHistoryJson())
        }
    }

    private fun persistChatHistorySync() {
        atomicWriteEncryptedText(historyFile(), buildHistoryJson())
    }

    private fun loadChatHistory() {
        try {
            val f = historyFile()
            if (!f.exists()) return
            val jsonText = readEncryptedTextOrNull(f) ?: try { f.readText() } catch (_: Exception) { null }
            if (jsonText == null) {
                statusMessage.value = tr(
                    "Chat history could not be read (file may be corrupted) - starting with empty history. Nothing else was affected.",
                    "चैट हिस्ट्री पढ़ी नहीं जा सकी (फ़ाइल करप्ट हो सकती है) - खाली हिस्ट्री से शुरू कर रहे हैं। बाकी कुछ भी प्रभावित नहीं हुआ।"
                )
                return
            }
            val arr = JSONArray(jsonText)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val session = ChatSession(
                    id = obj.getString("id"), title = obj.getString("title"), createdAt = obj.getLong("createdAt")
                )
                val msgArr = obj.getJSONArray("messages")
                for (j in 0 until msgArr.length()) {
                    val m = msgArr.getJSONObject(j)
                    session.messages.add(ChatMessage(
                        id = m.optString("id", UUID.randomUUID().toString()),
                        isUser = m.getBoolean("isUser"),
                        text = m.getString("text"),
                        timestamp = m.optLong("timestamp", System.currentTimeMillis())
                    ))
                }
                chatSessions.add(session)
            }
            currentSessionId.value = chatSessions.firstOrNull()?.id
        } catch (e: Exception) {
            statusMessage.value = tr(
                "Chat history file is corrupted and could not be loaded - starting fresh. Nothing else was affected.",
                "चैट हिस्ट्री फ़ाइल करप्ट है और लोड नहीं हो पाई - फ्रेश शुरू कर रहे हैं। बाकी कुछ भी प्रभावित नहीं हुआ।"
            )
        }
    }

    private fun reportsFile() = File(baseStorageDir(), "reports.json")

    private fun buildReportsJson(): String {
        val arr = JSONArray()
        reports.forEach { r ->
            arr.put(JSONObject().apply {
                put("id", r.id)
                put("timestamp", r.timestamp)
                put("reason", r.reason.name)
                put("comment", r.comment)
                put("aiResponseText", r.aiResponseText)
                put("modelName", r.modelName ?: JSONObject.NULL)
            })
        }
        return arr.toString()
    }

    private fun persistReports() {
        lifecycleScope.launch(Dispatchers.IO) {
            atomicWriteEncryptedText(reportsFile(), buildReportsJson())
        }
    }

    private fun persistReportsSync() {
        atomicWriteEncryptedText(reportsFile(), buildReportsJson())
    }

    private fun atomicWriteEncryptedText(target: File, content: String) {
        val lock = fileWriteLocks.getOrPut(target.absolutePath) { Any() }
        synchronized(lock) {
            try {
                val tmp = File(target.parentFile, "${target.name}.tmp")
                if (tmp.exists()) tmp.delete()
                val encrypted = CryptoManager.encrypt(content.toByteArray(Charsets.UTF_8))
                tmp.writeBytes(encrypted)

                if (!tmp.renameTo(target)) {
                    target.writeBytes(encrypted)
                    tmp.delete()
                }
            } catch (_: Exception) { }
        }
    }

    private fun readEncryptedTextOrNull(target: File): String? {
        if (!target.exists()) return null
        return try {
            CryptoManager.decrypt(target.readBytes()).toString(Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private val fileWriteLocks = java.util.concurrent.ConcurrentHashMap<String, Any>()

    private fun loadReports() {
        try {
            val f = reportsFile()
            if (!f.exists()) return
            val jsonText = readEncryptedTextOrNull(f) ?: try { f.readText() } catch (_: Exception) { null }
            if (jsonText == null) {
                statusMessage.value = tr(
                    "Saved reports could not be read (file may be corrupted).",
                    "सेव्ड रिपोर्ट्स पढ़ी नहीं जा सकीं (फ़ाइल करप्ट हो सकती है)।"
                )
                return
            }
            val arr = JSONArray(jsonText)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                reports.add(ReportEntry(
                    id = obj.getString("id"),
                    timestamp = obj.getLong("timestamp"),
                    reason = try { ReportReason.valueOf(obj.getString("reason")) } catch (_: Exception) { ReportReason.OTHER },
                    comment = obj.optString("comment", ""),
                    aiResponseText = obj.getString("aiResponseText"),
                    // Fixed: org.json's optString(name, fallback) has a well-known quirk —
                    // if the stored value is the JSONObject.NULL sentinel (not absent), it
                    // still calls .toString() on that sentinel, returning the literal
                    // STRING "null" instead of falling back. isNull() correctly treats both
                    // "missing" and "explicitly null" the same way, giving a real Kotlin
                    // null. This is also what caused the "inferred type Nothing?, but
                    // String was expected" warning from passing a null literal directly as
                    // optString's second (non-nullable-from-Kotlin's-view) parameter.
                    modelName = if (obj.isNull("modelName")) null else obj.optString("modelName")
                ))
            }
        } catch (e: Exception) {
            statusMessage.value = tr(
                "Saved reports file is corrupted and could not be loaded.",
                "सेव्ड रिपोर्ट्स फ़ाइल करप्ट है और लोड नहीं हो पाई।"
            )
        }
    }

    private fun reasonLabel(reason: ReportReason): String = when (reason) {
        ReportReason.OFFENSIVE -> tr("Offensive or inappropriate", "आपत्तिजनक या अनुचित")
        ReportReason.HARMFUL -> tr("Harmful or unsafe", "हानिकारक या असुरक्षित")
        ReportReason.HATE -> tr("Hate or harassment", "नफ़रत या उत्पीड़न")
        ReportReason.MISLEADING -> tr("Misleading/deceptive", "भ्रामक/धोखा देने वाला")
        ReportReason.OTHER -> tr("Other", "अन्य")
    }

    private fun submitReport(message: ChatMessage, reason: ReportReason, comment: String) {
        val entry = ReportEntry(
            reason = reason,
            comment = comment.trim(),
            aiResponseText = message.text,
            modelName = activeModelPath.value?.let { File(it).name }
        )
        reports.add(entry)
        persistReports()
        pendingReport.value = null
        submittedReport.value = entry
        statusMessage.value = tr("Report saved on this device.", "रिपोर्ट इस डिवाइस पर सेव हो गई।")
    }

    private fun shareReport(entry: ReportEntry, includePrompt: Boolean, precedingPrompt: String?) {
        val body = buildString {
            appendLine(tr("AI response report", "AI रिस्पॉन्स रिपोर्ट"))
            appendLine("${tr("Reason", "कारण")}: ${reasonLabel(entry.reason)}")
            if (entry.comment.isNotBlank()) appendLine("${tr("Comment", "टिप्पणी")}: ${entry.comment}")
            entry.modelName?.let { appendLine("${tr("Model", "मॉडल")}: $it") }
            if (includePrompt && !precedingPrompt.isNullOrBlank()) {
                appendLine()
                appendLine("${tr("User prompt", "यूज़र प्रॉम्प्ट")}:")
                appendLine(precedingPrompt)
            }
            appendLine()
            appendLine("${tr("AI response", "AI रिस्पॉन्स")}:")
            appendLine(entry.aiResponseText)
        }
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, tr("AI response report", "AI रिस्पॉन्स रिपोर्ट"))
            putExtra(Intent.EXTRA_TEXT, body)
        }
        startActivity(Intent.createChooser(sendIntent, tr("Share report", "रिपोर्ट शेयर करें")))
    }

    private fun sendChatMessage(userText: String): Boolean {
        val model = loadedModel
        if (model == null) {
            statusMessage.value = tr("Select a model in the Models tab first.", "पहले Models टैब से एक मॉडल चुनें।")
            return false
        }
        if (userText.isBlank()) return false
        if (isNativeCallActive.value) {
            val msg = tr(
                "Please wait - the previous response is still stopping.",
                "थोड़ा रुकिए - पिछला रिस्पॉन्स अभी रुक रहा है।"
            )
            statusMessage.value = msg
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            return false
        }

        val session = currentSession()
        session.messages.add(ChatMessage(isUser = true, text = userText))
        if (session.title.isBlank()) {
            session.title = if (userText.length > 40) "${userText.take(40)}..." else userText
        }
        isGenerating.value = true
        isStopping.value = false
        lastStats.value = ""

        generationJob = lifecycleScope.launch {
            try {
                val history = session.messages.joinToString("\n") { m -> if (m.isUser) "User: ${m.text}" else "Assistant: ${m.text}" }
                isNativeCallActive.value = true
                val result = withContext(Dispatchers.Default) {
                    Llama.complete(
                        model,
                        prompt = "$history\nAssistant:",
                        systemPrompt = "You are a helpful, concise assistant. Reply in the same " +
                                "language the user writes in (Hindi, Hinglish or English). " +
                                "Answer directly without repeating the question. " +
                                "When asked for a specific piece of information - a link, URL, " +
                                "code, name, number, or any concrete value - you MUST include " +
                                "that actual value in your reply. Never just say you provided it " +
                                "(e.g. never reply only 'Here is the link.' or 'Done.') without " +
                                "the real value itself present in the same message.",
                        maxTokens = maxTokens.intValue
                    )
                }
                val clean = result.text.trim().substringBefore("\nUser:").substringBefore("\nAssistant:").trim()
                session.messages.add(ChatMessage(isUser = false, text = clean))
                lastStats.value = "${result.tokensGenerated} tokens - %.1f tok/s".format(result.tokensPerSecond)
            } catch (e: CancellationException) {
                session.messages.add(ChatMessage(isUser = false, text = tr("[Stopped]", "[रोक दिया गया]")))
                throw e
            } catch (e: OutOfMemoryError) {
                unloadActiveModelSilently()
                session.messages.add(ChatMessage(isUser = false, text = tr("[Out of RAM - model unloaded]", "[RAM खत्म - मॉडल अनलोड कर दिया गया]")))
            } catch (e: Exception) {
                session.messages.add(ChatMessage(isUser = false, text = "[Error: ${e.message}]"))
            } finally {
                isGenerating.value = false
                isNativeCallActive.value = false
                isStopping.value = false
                persistChatHistory()
            }
        }
        return true
    }

    private fun stopGeneration() {
        if (!isGenerating.value) return
        isStopping.value = true
        generationJob?.cancel()
        generationJob = null
        isGenerating.value = false
    }

    override fun onDestroy() {
        generationJob?.cancel()

        persistChatHistorySync()
        persistReportsSync()

        val modelToRelease = loadedModel
        loadedModel = null
        if (modelToRelease != null) {
            AppScope.scope.launch {
                withTimeoutOrNull(10_000) { while (isNativeCallActive.value) delay(50) }
                try { Llama.releaseModel(modelToRelease) } catch (_: Exception) { }
            }
        }

        super.onDestroy()
    }

    // ---------- UI ----------

    @Composable
    private fun AppRoot() {
        var screen by rememberSaveable { mutableStateOf(Screen.MODELS) }

        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing,
            bottomBar = {
                NavigationBar(windowInsets = NavigationBarDefaults.windowInsets) {
                    NavigationBarItem(
                        selected = screen == Screen.MODELS, onClick = { screen = Screen.MODELS },
                        icon = { Icon(Icons.AutoMirrored.Filled.List, contentDescription = null) },
                        label = { Text(tr("Models", "मॉडल्स")) }
                    )
                    NavigationBarItem(
                        selected = screen == Screen.CHAT, onClick = { screen = Screen.CHAT },
                        icon = { Icon(Icons.Filled.MailOutline, contentDescription = null) },
                        label = { Text(tr("Chat", "चैट")) }
                    )
                    NavigationBarItem(
                        selected = screen == Screen.SETTINGS, onClick = { screen = Screen.SETTINGS },
                        icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                        label = { Text(tr("Settings", "सेटिंग्स")) }
                    )
                }
            }
        ) { padding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .consumeWindowInsets(padding)
                    .imePadding()
            ) {
                when (screen) {
                    Screen.MODELS -> ModelsScreen()
                    Screen.CHAT -> ChatScreen()
                    Screen.SETTINGS -> SettingsScreen()
                }
            }
        }
    }

    @Composable
    private fun ModelsScreen() {
        var pendingDelete by remember { mutableStateOf<ModelEntry?>(null) }

        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(tr("GGUF Models", "GGUF मॉडल्स"), style = MaterialTheme.typography.headlineSmall)
            Text(
                tr(
                    "This app has no internet permission and makes no network requests. Download a .gguf model file yourself (e.g. from Hugging Face) using any app, then select it below.",
                    "इस ऐप में इंटरनेट परमिशन नहीं है और यह कोई नेटवर्क रिक्वेस्ट नहीं करती। किसी भी ऐप से (जैसे ब्राउज़र) .gguf मॉडल फ़ाइल खुद डाउनलोड करके नीचे से चुनें।"
                ),
                style = MaterialTheme.typography.bodySmall
            )

            OutlinedButton(onClick = { safPickerLauncher.launch(arrayOf("*/*")) }, enabled = !isModelBusy.value) {
                Text(tr("Pick from device", "डिवाइस से चुनें"))
            }

            if (isModelBusy.value) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            if (statusMessage.value.isNotBlank()) {
                Text(statusMessage.value, style = MaterialTheme.typography.bodySmall)
            }

            HorizontalDivider()
            Text(tr("Installed (${models.size})", "इंस्टॉल्ड (${models.size})"), style = MaterialTheme.typography.titleMedium)

            if (models.isEmpty()) {
                Text(
                    tr("No models yet. Tap 'Pick from device' to add one.", "अभी कोई मॉडल नहीं है। 'डिवाइस से चुनें' दबाकर एक जोड़ें।"),
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(models, key = { it.file.absolutePath }) { entry ->
                    ModelCard(
                        entry = entry, isActive = activeModelPath.value == entry.file.absolutePath, isBusy = isModelBusy.value,
                        onSelect = { selectActiveModel(entry) }, onDelete = { pendingDelete = entry }
                    )
                }
            }
        }

        pendingDelete?.let { entry ->
            AlertDialog(
                onDismissRequest = { pendingDelete = null },
                title = { Text(tr("Delete model?", "मॉडल डिलीट करें?")) },
                text = { Text(tr("${entry.name} (${entry.sizeMb} MB) will be permanently deleted.", "${entry.name} (${entry.sizeMb} MB) हमेशा के लिए डिलीट हो जाएगा।")) },
                confirmButton = { TextButton(onClick = { deleteModel(entry); pendingDelete = null }) { Text(tr("Delete", "डिलीट करें")) } },
                dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text(tr("Cancel", "रद्द करें")) } }
            )
        }

        pendingRiskyLoad.value?.let { (entry, reason) ->
            AlertDialog(
                onDismissRequest = { pendingRiskyLoad.value = null },
                title = { Text(tr("Low RAM available", "कम RAM उपलब्ध है")) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(entry.name, fontWeight = FontWeight.Bold)
                        Text(reason, style = MaterialTheme.typography.bodySmall)
                    }
                },
                confirmButton = {
                    TextButton(onClick = { val t = entry; pendingRiskyLoad.value = null; loadModelInternal(t) }) {
                        Text(tr("Try loading anyway", "फिर भी लोड करें"))
                    }
                },
                dismissButton = { TextButton(onClick = { pendingRiskyLoad.value = null }) { Text(tr("Cancel", "रद्द करें")) } }
            )
        }
    }

    @Composable
    private fun ModelCard(entry: ModelEntry, isActive: Boolean, isBusy: Boolean, onSelect: () -> Unit, onDelete: () -> Unit) {
        val dateStr = remember(entry.lastModified) { SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.getDefault()).format(Date(entry.lastModified)) }
        val quant = remember(entry.name) { Regex("(?i)\\bq\\d(_[a-z0-9]+)*\\b").find(entry.name)?.value?.uppercase() ?: "-" }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(entry.name, fontWeight = FontWeight.Bold)
                Text("${entry.sizeMb} MB - ${tr("quant", "क्वांट")} $quant", style = MaterialTheme.typography.bodySmall)
                Text(tr("Added $dateStr", "जोड़ा गया: $dateStr"), style = MaterialTheme.typography.bodySmall)
                Text(
                    tr(
                        "Approximate RAM requirement: ~${estimateRequiredBytes(entry.sizeBytes, contextSize.intValue) / (1024 * 1024)} MB",
                        "अनुमानित RAM ज़रूरत: ~${estimateRequiredBytes(entry.sizeBytes, contextSize.intValue) / (1024 * 1024)} MB"
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
                if (isActive) {
                    Text(tr("Active", "सक्रिय"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                    Button(onClick = onSelect, enabled = !isBusy && !isActive) { Text(if (isActive) tr("In use", "इस्तेमाल में") else tr("Use", "इस्तेमाल करें")) }
                    OutlinedButton(onClick = onDelete, enabled = !isBusy) { Text(tr("Delete", "डिलीट करें")) }
                }
            }
        }
    }

    @Composable
    private fun ChatScreen() {
        var input by rememberSaveable { mutableStateOf("") }
        var showHistory by remember { mutableStateOf(false) }
        var showClearConfirm by remember { mutableStateOf(false) }
        var nowLabel by remember { mutableStateOf(currentDateTimeLabel()) }
        val listState = rememberLazyListState()
        val session = currentSession()
        val activeName = activeModelPath.value?.let { File(it).name } ?: tr("No model loaded", "कोई मॉडल लोड नहीं है")
        // Modern Clipboard API (suspend-based) — LocalClipboardManager/ClipboardManager are
        // deprecated in favor of this. Writes need a CoroutineScope since setClipEntry is suspend.
        val clipboard = LocalClipboard.current
        val clipboardScope = rememberCoroutineScope()
        val context = LocalContext.current

        LaunchedEffect(Unit) {
            while (true) { nowLabel = currentDateTimeLabel(); delay(30_000) }
        }
        LaunchedEffect(session.messages.size, isGenerating.value, isStopping.value) {
            val target = session.messages.size
            if (target > 0) listState.animateScrollToItem(target)
        }

        Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        session.title.ifBlank { tr("New Chat", "नई चैट") },
                        style = MaterialTheme.typography.titleSmall, maxLines = 1
                    )
                    Text(activeName, style = MaterialTheme.typography.labelSmall)
                }
                IconButton(onClick = { showHistory = true }) { Icon(Icons.Filled.Menu, contentDescription = tr("Chat history", "चैट हिस्ट्री")) }
                IconButton(onClick = { startNewChat() }) { Icon(Icons.Filled.Add, contentDescription = tr("New chat", "नई चैट")) }
                TextButton(onClick = { showClearConfirm = true }, enabled = session.messages.isNotEmpty()) { Text(tr("Clear", "क्लियर")) }
                if (activeModelPath.value != null) {
                    TextButton(onClick = { unloadActiveModel() }, enabled = !isModelBusy.value) { Text(tr("Unload", "अनलोड")) }
                }
            }
            Text(
                nowLabel,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp, bottom = 4.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )

            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                SelectionContainer(modifier = Modifier.fillMaxSize()) {
                    LazyColumn(state = listState, modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(session.messages, key = { it.id }) { msg ->
                            Column(modifier = Modifier.fillMaxWidth()) {
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = if (msg.isUser) Arrangement.End else Arrangement.Start) {
                                    Card(
                                        modifier = Modifier.fillMaxWidth(0.85f),
                                        colors = CardDefaults.cardColors(
                                            containerColor = if (msg.isUser) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
                                        )
                                    ) {
                                        Box(modifier = Modifier.padding(10.dp)) {
                                            MessageContent(text = msg.text, clipboard = clipboard, scope = clipboardScope, context = context)
                                        }
                                    }
                                }
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = if (msg.isUser) Arrangement.End else Arrangement.Start) {
                                    Text(
                                        remember(msg.timestamp) { SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(msg.timestamp)) },
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(horizontal = 4.dp)
                                    )
                                }
                                if (!msg.isUser) {
                                    var menuExpanded by remember(msg.id) { mutableStateOf(false) }
                                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Start) {
                                        Box {
                                            IconButton(onClick = { menuExpanded = true }, modifier = Modifier.size(28.dp)) {
                                                Icon(Icons.Filled.MoreVert, contentDescription = tr("More options", "और विकल्प"), modifier = Modifier.size(18.dp))
                                            }
                                            DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                                                DropdownMenuItem(
                                                    text = { Text(tr("Copy", "कॉपी करें")) },
                                                    onClick = {
                                                        menuExpanded = false
                                                        clipboardScope.launch {
                                                            clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("message", msg.text)))
                                                        }
                                                        Toast.makeText(context, tr("Copied", "कॉपी हो गया"), Toast.LENGTH_SHORT).show()
                                                    }
                                                )
                                                DropdownMenuItem(
                                                    text = { Text(tr("Report response", "रिस्पॉन्स रिपोर्ट करें")) },
                                                    onClick = { menuExpanded = false; pendingReport.value = msg }
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (isGenerating.value) { item { TypingIndicator() } }
                        if (isStopping.value) { item { StoppingIndicator() } }
                    }
                }
            }

            if (lastStats.value.isNotBlank()) { Text(lastStats.value, style = MaterialTheme.typography.labelSmall) }

            Row(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = input, onValueChange = { input = it }, modifier = Modifier.weight(1f),
                    label = { Text(tr("Message", "मैसेज")) },
                    enabled = activeModelPath.value != null && !isGenerating.value
                )
                Spacer(modifier = Modifier.width(8.dp))
                if (isGenerating.value) {
                    Button(onClick = { stopGeneration() }, colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)) {
                        Text(tr("Stop", "रोकें"))
                    }
                } else {
                    Button(
                        onClick = {
                            val text = input.trim()
                            if (text.isNotBlank() && sendChatMessage(text)) input = ""
                        },
                        enabled = activeModelPath.value != null && input.isNotBlank()
                    ) { Text(tr("Send", "भेजें")) }
                }
            }
        }

        if (showHistory) {
            ChatHistoryDialog(
                onDismiss = { showHistory = false },
                onOpen = { id -> switchToSession(id); showHistory = false },
                onDelete = { id -> deleteSession(id) },
                onRename = { id, title -> renameSession(id, title) }
            )
        }

        if (showClearConfirm) {
            AlertDialog(
                onDismissRequest = { showClearConfirm = false },
                title = { Text(tr("Clear this chat?", "यह चैट क्लियर करें?")) },
                text = { Text(tr("Removes all messages in this chat, but keeps the chat itself in your history.", "यह इस चैट के सारे मैसेज हटा देता है, लेकिन चैट खुद आपकी हिस्ट्री में रहती है।")) },
                confirmButton = { TextButton(onClick = { clearCurrentChat(); showClearConfirm = false }) { Text(tr("Clear", "क्लियर")) } },
                dismissButton = { TextButton(onClick = { showClearConfirm = false }) { Text(tr("Cancel", "रद्द करें")) } }
            )
        }

        pendingReport.value?.let { msg ->
            val precedingPrompt = remember(msg.id) {
                val idx = session.messages.indexOfFirst { it.id == msg.id }
                if (idx > 0) session.messages[idx - 1].takeIf { it.isUser }?.text else null
            }
            ReportDialog(
                onDismiss = { pendingReport.value = null },
                onSubmit = { reason, comment -> submitReport(msg, reason, comment) }
            )
            LaunchedEffect(msg.id) { lastPrecedingPrompt = precedingPrompt }
        }

        submittedReport.value?.let { entry ->
            ReportConfirmDialog(
                entry = entry,
                precedingPrompt = lastPrecedingPrompt,
                onClose = { submittedReport.value = null },
                onShare = { includePrompt -> shareReport(entry, includePrompt, lastPrecedingPrompt) }
            )
        }
    }

    private var lastPrecedingPrompt: String? by mutableStateOf(null)

    @Composable
    private fun ReportDialog(onDismiss: () -> Unit, onSubmit: (ReportReason, String) -> Unit) {
        var selectedReason by remember { mutableStateOf<ReportReason?>(null) }
        var comment by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(tr("Report response", "रिस्पॉन्स रिपोर्ट करें")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ReportReason.entries.forEach { reason ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth().clickable { selectedReason = reason }
                        ) {
                            RadioButton(selected = selectedReason == reason, onClick = { selectedReason = reason })
                            Text(reasonLabel(reason))
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = comment, onValueChange = { comment = it },
                        label = { Text(tr("Additional comment (optional)", "अतिरिक्त टिप्पणी (वैकल्पिक)")) },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        tr(
                            "This report is saved only on your device. It is not sent anywhere automatically.",
                            "यह रिपोर्ट सिर्फ़ आपके डिवाइस पर सेव होती है। यह कहीं भी अपने आप नहीं भेजी जाती।"
                        ),
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { selectedReason?.let { onSubmit(it, comment) } },
                    enabled = selectedReason != null
                ) { Text(tr("Submit", "सबमिट करें")) }
            },
            dismissButton = { TextButton(onClick = onDismiss) { Text(tr("Cancel", "रद्द करें")) } }
        )
    }

    @Composable
    private fun ReportConfirmDialog(
        entry: ReportEntry,
        precedingPrompt: String?,
        onClose: () -> Unit,
        onShare: (includePrompt: Boolean) -> Unit
    ) {
        var includePrompt by remember { mutableStateOf(false) }

        AlertDialog(
            onDismissRequest = onClose,
            title = { Text(tr("Report saved", "रिपोर्ट सेव हो गई")) },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(tr("Reason", "कारण") + ": " + reasonLabel(entry.reason), fontWeight = FontWeight.Bold)
                    if (entry.comment.isNotBlank()) Text("${tr("Comment", "टिप्पणी")}: ${entry.comment}")
                    entry.modelName?.let { Text("${tr("Model", "मॉडल")}: $it", style = MaterialTheme.typography.labelSmall) }
                    HorizontalDivider()
                    Text(tr("AI response:", "AI रिस्पॉन्स:"), fontWeight = FontWeight.Bold)
                    Text(entry.aiResponseText, style = MaterialTheme.typography.bodySmall)

                    if (!precedingPrompt.isNullOrBlank()) {
                        HorizontalDivider()
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { includePrompt = !includePrompt }) {
                            Checkbox(checked = includePrompt, onCheckedChange = { includePrompt = it })
                            Text(tr("Include my original message when sharing", "शेयर करते समय मेरा असली मैसेज भी शामिल करें"))
                        }
                        if (includePrompt) {
                            Text(precedingPrompt, style = MaterialTheme.typography.bodySmall)
                        }
                    }

                    Text(
                        tr(
                            "Sharing is optional. If you tap Share, Android's own share sheet opens and you choose the recipient - nothing is sent automatically.",
                            "शेयर करना वैकल्पिक है। अगर आप शेयर दबाते हैं, तो Android की अपनी शेयर शीट खुलती है और आप खुद प्राप्तकर्ता चुनते हैं - कुछ भी अपने आप नहीं भेजा जाता।"
                        ),
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { onShare(includePrompt); onClose() }) { Text(tr("Share report (email, etc.)", "शेयर करें (ईमेल, आदि)")) }
            },
            dismissButton = { TextButton(onClick = onClose) { Text(tr("Close", "बंद करें")) } }
        )
    }

    @Composable
    private fun MessageContent(
        text: String,
        clipboard: androidx.compose.ui.platform.Clipboard,
        scope: CoroutineScope,
        context: android.content.Context
    ) {
        val codeRegex = remember { Regex("```[a-zA-Z0-9_+-]*\\n?([\\s\\S]*?)```") }
        val parts = remember(text) {
            val result = mutableListOf<Pair<Boolean, String>>()
            var lastIndex = 0
            for (match in codeRegex.findAll(text)) {
                if (match.range.first > lastIndex) result.add(false to text.substring(lastIndex, match.range.first))
                result.add(true to match.groupValues[1].trim('\n'))
                lastIndex = match.range.last + 1
            }
            if (lastIndex < text.length) result.add(false to text.substring(lastIndex))
            if (result.isEmpty()) result.add(false to text)
            result
        }

        Column {
            parts.forEach { (isCode, content) ->
                if (isCode) {
                    Card(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFF8BBD0))
                    ) {
                        Column(Modifier.padding(8.dp)) {
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                TextButton(onClick = {
                                    scope.launch {
                                        clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("code", content)))
                                    }
                                    Toast.makeText(context, tr("Copied", "कॉपी हो गया"), Toast.LENGTH_SHORT).show()
                                }) { Text(tr("Copy", "कॉपी करें"), color = Color.Black) }
                            }
                            Text(content, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = Color.Black)
                        }
                    }
                } else if (content.isNotBlank()) {
                    // Real markdown parsing via org.jetbrains:markdown (CommonMark/GFM
                    // compliant) instead of the previous hand-rolled regex parser —
                    // headings, bold, italic, lists, blockquotes, inline code, and
                    // (thanks to GFM) bare-URL autolinks are all handled by the library
                    // itself, not by a set of ad-hoc regexes.
                    Text(markdownToAnnotatedString(content.trim()))
                }
            }
        }
    }

    /**
     * Parses markdown with org.jetbrains:markdown (GFM flavour — adds GitHub-style
     * extras over plain CommonMark, notably autolinking bare URLs, which AI replies
     * frequently contain without [label](url) wrapping), renders the parsed tree to
     * HTML, then converts that HTML into a Compose AnnotatedString. Compose's own
     * fromHtml() turns <a href> tags into genuinely clickable LinkAnnotation spans
     * automatically — no manual link-detection regex needed here anymore.
     */
    private fun markdownToAnnotatedString(markdown: String): AnnotatedString {
        val flavour = GFMFlavourDescriptor()
        // Calling the full (flavour, assertionsEnabled, cancellationToken) constructor
        // and the CharSequence overload of buildMarkdownTreeFromString explicitly — the
        // shorter constructor and the String overload both just forward to these with a
        // default CancellationToken, and are marked deprecated in this library version.
        val parsedTree = MarkdownParser(flavour, true, CancellationToken.NonCancellable)
            .buildMarkdownTreeFromString(markdown as CharSequence)
        val html = HtmlGenerator(markdown, parsedTree, flavour).generateHtml()
        return AnnotatedString.fromHtml(
            htmlString = html,
            linkStyles = TextLinkStyles(style = SpanStyle(color = Color(0xFF1565C0)))
        )
    }

    private fun currentDateTimeLabel(): String =
        SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.getDefault()).format(Date())

    @Composable
    private fun ChatHistoryDialog(
        onDismiss: () -> Unit, onOpen: (String) -> Unit, onDelete: (String) -> Unit, onRename: (String, String) -> Unit
    ) {
        var renaming by remember { mutableStateOf<ChatSession?>(null) }

        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(tr("Chat history", "चैट हिस्ट्री")) },
            text = {
                LazyColumn(modifier = Modifier.heightIn(max = 420.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(chatSessions.sortedByDescending { it.createdAt }, key = { it.id }) { session ->
                        val isActive = session.id == currentSessionId.value
                        val dateStr = remember(session.createdAt) {
                            SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.getDefault()).format(Date(session.createdAt))
                        }
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isActive) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
                            ),
                            border = if (isActive) BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary) else null,
                            onClick = { onOpen(session.id) }
                        ) {
                            Column(Modifier.padding(10.dp)) {
                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text(dateStr, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold)
                                    if (isActive) Text(tr("Current", "मौजूदा"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelSmall)
                                }
                                Text(session.title.ifBlank { tr("New Chat", "नई चैट") }, fontWeight = FontWeight.Bold, maxLines = 1)
                                Text(tr("${session.messages.size} messages", "${session.messages.size} मैसेज"), style = MaterialTheme.typography.labelSmall)
                                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                    TextButton(onClick = { renaming = session }) { Text(tr("Rename", "नाम बदलें")) }
                                    TextButton(onClick = { onDelete(session.id) }) {
                                        Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(Modifier.width(4.dp))
                                        Text(tr("Delete", "डिलीट करें"))
                                    }
                                }
                            }
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = onDismiss) { Text(tr("Close", "बंद करें")) } }
        )

        renaming?.let { session ->
            var newTitle by remember(session.id) { mutableStateOf(session.title) }
            AlertDialog(
                onDismissRequest = { renaming = null },
                title = { Text(tr("Rename chat", "चैट का नाम बदलें")) },
                text = { OutlinedTextField(value = newTitle, onValueChange = { newTitle = it }, singleLine = true) },
                confirmButton = { TextButton(onClick = { onRename(session.id, newTitle); renaming = null }) { Text(tr("Save", "सेव करें")) } },
                dismissButton = { TextButton(onClick = { renaming = null }) { Text(tr("Cancel", "रद्द करें")) } }
            )
        }
    }

    @Composable
    private fun TypingIndicator() {
        val transition = rememberInfiniteTransition(label = "typing")
        Card(modifier = Modifier.fillMaxWidth(0.4f), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Row(modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                repeat(3) { index ->
                    val alpha by transition.animateFloat(
                        initialValue = 0.25f, targetValue = 1f,
                        animationSpec = infiniteRepeatable(animation = tween(600, delayMillis = index * 200, easing = LinearEasing), repeatMode = RepeatMode.Reverse),
                        label = "dot$index"
                    )
                    Box(modifier = Modifier.size(8.dp).alpha(alpha)) {
                        Surface(modifier = Modifier.fillMaxSize(), shape = MaterialTheme.shapes.small, color = MaterialTheme.colorScheme.onSurfaceVariant) {}
                    }
                }
            }
        }
    }

    @Composable
    private fun StoppingIndicator() {
        Row(
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            horizontalArrangement = Arrangement.Start,
            verticalAlignment = Alignment.CenterVertically
        ) {
            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                tr("Stopping previous response...", "पिछला रिस्पॉन्स रोका जा रहा है..."),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }

    @Composable
    private fun SettingsScreen() {
        var showPrivacy by remember { mutableStateOf(false) }
        var showLicenses by remember { mutableStateOf(false) }
        var showDeleteAllConfirm by remember { mutableStateOf(false) }
        var mem by remember { mutableStateOf(readDeviceMemory()) }
        val appVersionLabel = remember {
            try {
                // getPackageInfo(String, int) is deprecated since API 33 in favor of the
                // PackageInfoFlags overload. minSdk is 30, so the flags overload (API 33+)
                // isn't available on every supported device — this branches so neither
                // path uses a deprecated call on the API level it actually runs on. The
                // @Suppress below is unavoidable for API 30-32, where only the old
                // overload exists at all.
                val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getPackageInfo(packageName, 0)
                }
                "${info.versionName} (${info.longVersionCode})"
            } catch (e: Exception) { "unknown" }
        }

        LaunchedEffect(Unit) { while (true) { mem = readDeviceMemory(); delay(2000) } }

        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(tr("Settings", "सेटिंग्स"), style = MaterialTheme.typography.headlineSmall)

            Text(tr("Language", "भाषा"), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = appLanguage.value == AppLanguage.EN, onClick = { setLanguage(AppLanguage.EN) }, label = { Text("English") })
                FilterChip(selected = appLanguage.value == AppLanguage.HI, onClick = { setLanguage(AppLanguage.HI) }, label = { Text("हिंदी") })
            }

            Text(tr("Appearance", "दिखावट"), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = themeMode.value == ThemeMode.LIGHT, onClick = { setThemeMode(ThemeMode.LIGHT) }, label = { Text(tr("Light", "लाइट")) })
                FilterChip(selected = themeMode.value == ThemeMode.DARK, onClick = { setThemeMode(ThemeMode.DARK) }, label = { Text(tr("Dark", "डार्क")) })
                FilterChip(selected = themeMode.value == ThemeMode.SYSTEM, onClick = { setThemeMode(ThemeMode.SYSTEM) }, label = { Text(tr("System", "फ़ोन जैसा")) })
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(tr("Device", "डिवाइस"), fontWeight = FontWeight.Bold)
                    Text("${tr("Model", "मॉडल")}: ${Build.MANUFACTURER} ${Build.MODEL}", style = MaterialTheme.typography.bodySmall)
                    Text("Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})", style = MaterialTheme.typography.bodySmall)
                    Text("CPU: ${Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"} - ${Runtime.getRuntime().availableProcessors()} ${tr("cores", "कोर")}", style = MaterialTheme.typography.bodySmall)
                    Text("${tr("RAM", "RAM")}: ${mem.availableBytes / (1024 * 1024)} MB ${tr("free of", "उपलब्ध, कुल")} ${mem.totalBytes / (1024 * 1024)} MB", style = MaterialTheme.typography.bodySmall)
                    Text("${tr("App storage", "ऐप स्टोरेज")}: ${modelsDir.usableSpace / (1024 * 1024)} MB ${tr("free", "फ्री")}", style = MaterialTheme.typography.bodySmall)
                    Text("${tr("Active model", "सक्रिय मॉडल")}: ${activeModelPath.value?.let { File(it).name } ?: tr("none", "कोई नहीं")}", style = MaterialTheme.typography.bodySmall)
                }
            }

            Text(tr("Inference", "इन्फरेंस"), style = MaterialTheme.typography.titleMedium)
            Text(tr("Changes apply next time a model is loaded - tap 'Use' again on the Models tab.", "बदलाव अगली बार मॉडल लोड होने पर लागू होंगे - Models टैब में 'इस्तेमाल करें' दोबारा दबाएँ।"), style = MaterialTheme.typography.bodySmall)

            SettingSlider(tr("Threads", "थ्रेड्स"), threads.intValue, 1..Runtime.getRuntime().availableProcessors()) { threads.intValue = it }
            SettingSlider(tr("Context size (higher = more RAM)", "कॉन्टेक्स्ट साइज़ (ज़्यादा = ज़्यादा RAM)"), contextSize.intValue, 256..4096, 256) { contextSize.intValue = it }
            SettingSlider(tr("Max tokens per reply", "प्रति रिप्लाई अधिकतम टोकन"), maxTokens.intValue, 20..512, 10) { maxTokens.intValue = it }

            HorizontalDivider()

            Text(tr("About", "ऐप के बारे में"), style = MaterialTheme.typography.titleMedium)
            Text("${tr("Version", "वर्शन")} $appVersionLabel", style = MaterialTheme.typography.bodySmall)
            Card(modifier = Modifier.fillMaxWidth()) {
                Text(
                    tr(
                        "AI responses are generated locally by the GGUF model selected by the user. Responses may be inaccurate, incomplete, or inappropriate. The developer does not control the selected model or guarantee the accuracy of generated content.",
                        "AI के जवाब यूज़र के चुने हुए GGUF मॉडल द्वारा आपके डिवाइस पर लोकली जनरेट होते हैं। जवाब गलत, अधूरे, या अनुचित हो सकते हैं। डेवलपर चुने गए मॉडल को नियंत्रित नहीं करता और जनरेट किए गए कंटेंट की सटीकता की गारंटी नहीं देता।"
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(12.dp)
                )
            }
            OutlinedButton(onClick = { showPrivacy = true }, modifier = Modifier.fillMaxWidth()) { Text(tr("Privacy Policy", "प्राइवेसी पॉलिसी")) }
            OutlinedButton(onClick = { showLicenses = true }, modifier = Modifier.fillMaxWidth()) { Text(tr("Open Source Licenses", "ओपन सोर्स लाइसेंस")) }

            HorizontalDivider()

            Text(tr("Data", "डेटा"), style = MaterialTheme.typography.titleMedium)
            Text(
                tr(
                    "Permanently deletes every model, all chat history, and all saved reports from this device.",
                    "यह डिवाइस से हर मॉडल, सारी चैट हिस्ट्री, और सारी सेव्ड रिपोर्ट्स हमेशा के लिए डिलीट कर देता है।"
                ),
                style = MaterialTheme.typography.bodySmall
            )
            Button(
                onClick = { showDeleteAllConfirm = true },
                enabled = !isModelBusy.value,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.fillMaxWidth()
            ) { Text(tr("Delete All Data", "सारा डेटा डिलीट करें")) }

            Spacer(Modifier.height(8.dp))
        }

        if (showPrivacy) InfoDialog(tr("Privacy Policy", "प्राइवेसी पॉलिसी"), if (appLanguage.value == AppLanguage.HI) PRIVACY_POLICY_HI else PRIVACY_POLICY_EN) { showPrivacy = false }
        if (showLicenses) InfoDialog(tr("Open Source Licenses", "ओपन सोर्स लाइसेंस"), if (appLanguage.value == AppLanguage.HI) LICENSES_HI else LICENSES_EN) { showLicenses = false }

        if (showDeleteAllConfirm) {
            AlertDialog(
                onDismissRequest = { showDeleteAllConfirm = false },
                title = { Text(tr("Delete all data?", "सारा डेटा डिलीट करें?")) },
                text = {
                    Text(
                        tr(
                            "This permanently deletes every model file, all chat history, and all saved reports from this device. This cannot be undone.",
                            "यह इस डिवाइस से हर मॉडल फ़ाइल, सारी चैट हिस्ट्री, और सारी सेव्ड रिपोर्ट्स हमेशा के लिए डिलीट कर देता है। इसे वापस नहीं लाया जा सकता।"
                        )
                    )
                },
                confirmButton = {
                    TextButton(onClick = { clearAllUserData(); showDeleteAllConfirm = false }) {
                        Text(tr("Delete Everything", "सब कुछ डिलीट करें"))
                    }
                },
                dismissButton = { TextButton(onClick = { showDeleteAllConfirm = false }) { Text(tr("Cancel", "रद्द करें")) } }
            )
        }
    }

    private fun linkifyText(text: String): AnnotatedString = buildAnnotatedString {
        val urlRegex = Regex("https?://\\S+")
        var lastIndex = 0
        for (match in urlRegex.findAll(text)) {
            if (match.range.first > lastIndex) append(text.substring(lastIndex, match.range.first))
            val url = match.value.trimEnd('.', ',', ')', ']')
            withLink(
                LinkAnnotation.Url(
                    url,
                    TextLinkStyles(style = SpanStyle(color = Color(0xFF1565C0)))
                )
            ) { append(url) }
            val trailingPunct = match.value.removePrefix(url)
            if (trailingPunct.isNotEmpty()) append(trailingPunct)
            lastIndex = match.range.last + 1
        }
        if (lastIndex < text.length) append(text.substring(lastIndex))
    }

    @Composable
    private fun InfoDialog(title: String, body: String, onDismiss: () -> Unit) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(title) },
            text = { Column(modifier = Modifier.verticalScroll(rememberScrollState())) { Text(linkifyText(body), style = MaterialTheme.typography.bodySmall) } },
            confirmButton = { TextButton(onClick = onDismiss) { Text(tr("Close", "बंद करें")) } }
        )
    }

    @Composable
    private fun SettingSlider(label: String, value: Int, range: IntRange, step: Int = 1, onChange: (Int) -> Unit) {
        Column {
            Text("$label: $value")
            Slider(
                value = value.toFloat(),
                onValueChange = { raw -> onChange(((raw / step).toInt() * step).coerceIn(range.first, range.last)) },
                valueRange = range.first.toFloat()..range.last.toFloat()
            )
        }
    }

    private companion object {
        const val PRIVACY_POLICY_EN = """
Privacy Policy - RS GGUF Runner
Last updated: September 6, 2026

This app runs language models entirely on your device. It has no internet permission and makes no network requests of any kind. It has no user account, no ads, no analytics, and no backend server of any kind.

What the developer collects remotely: nothing, ever. There is no network connection through which any data from this app could reach the developer or anyone else. Everything described below happens only on your own device.

What the app itself can access/store locally on your device: your prompts and the AI's responses (processed only in memory while you chat), chat history, the GGUF model files you select, and any reports you create using "Report response" - all of this stays inside the app's own local storage on your device.

Prompts and AI responses: everything you type, and every response generated by the AI model, is processed entirely on your device by the GGUF model you selected. Nothing you type or receive is transmitted anywhere by this app.

Chat history: stored locally on your device, inside this app's private storage, so you can revisit past conversations. Deleted when you delete that chat here or uninstall the app. The chat history file is encrypted at rest using a key generated and held inside the Android Keystore (hardware-backed on devices that support it), which is designed to make the file unreadable without that key if it were ever extracted from the device. As with any security implementation, we are not able to promise that this is unbreakable in every circumstance (for example, on a compromised or rooted device), and we make no warranty of absolute security.

Model files: you select a .gguf model file yourself from your device's storage using Android's system file picker; this app never fetches, verifies, or updates a model over the internet. Selected model files are stored locally in this app's private storage and removed when you delete them from the Models screen or uninstall the app.

AI response reports: if you use "Report response" on an AI reply, the report (the reason you selected, your optional comment, the AI response text, and the model name) is saved only in this app's local, private storage, encrypted at rest the same way chat history is. It is NOT automatically sent to the developer or to anyone else. If you choose "Share report (email, etc.)" after reviewing it, Android's own system Share Sheet opens, and you personally choose which app or contact to send it to - this app has no part in that transmission beyond handing the text to the share sheet you opened. Your original prompt is included in a shared report only if you explicitly tick "Include my original message" - it is never included by default.

Backups: this app sets android:allowBackup="false" in its configuration, and in addition, chat history, model files, and reports are all stored under Android's dedicated no-backup storage area (getNoBackupFilesDir). Both of these are Android's standard, documented mechanisms for excluding data from cloud Auto Backup and device-to-device transfer, and they are how this app is designed to behave. That said, behavior can vary across manufacturers, OS versions, and custom Android builds outside of our control, so we are not able to promise this outcome in every possible circumstance.

Permissions: this app requests no internet permission and no storage permission. Model files are picked through Android's system file picker, which grants access only to the single file you choose.

Deleting your data: Settings has a "Delete All Data" button that is designed to permanently delete every model file, all chat history, and all saved reports from this device's app storage in one action, and this action cannot be reversed within the app. You can also delete things individually - a single model from the Models screen, a single chat from Chat History, or simply uninstall the app, which removes the app's storage. We rely on the standard file-deletion mechanisms provided by Android; we do not make any representation about whether data could still be recovered from the underlying storage hardware through specialized means outside of the app and the operating system's control.

Disclaimer: this app, its AI-generated responses, and its features are provided on an "as is" and "as available" basis, without warranties of any kind, express or implied, including but not limited to accuracy, reliability, fitness for a particular purpose, or uninterrupted availability. While the app is designed with the privacy and security practices described above, we do not guarantee that any particular security, privacy, backup-exclusion, or data-deletion outcome will hold in every circumstance, device, or Android version. You use this app, and any content it generates, at your own discretion and risk. To the maximum extent permitted by applicable law, the developer disclaims liability for any loss, damage, or issue arising from your use of this app.

Children: this app is not directed at children under 13.

Developer: Ram Singh Yadav
Contact: sys7userui@gmail.com
"""

        const val PRIVACY_POLICY_HI = """
प्राइवेसी पॉलिसी - RS GGUF Runner
आख़िरी बार अपडेट किया गया: 6 सितंबर, 2026

यह ऐप लैंग्वेज मॉडल्स को पूरी तरह आपके डिवाइस पर चलाता है। इसमें कोई इंटरनेट परमिशन नहीं है और यह किसी भी तरह की नेटवर्क रिक्वेस्ट नहीं करता। इसमें कोई यूज़र अकाउंट, विज्ञापन, एनालिटिक्स, या किसी भी तरह का बैकएंड सर्वर नहीं है।

डेवलपर दूर से क्या कलेक्ट करता है: कुछ भी नहीं, कभी नहीं। कोई नेटवर्क कनेक्शन ही नहीं है जिससे इस ऐप का कोई भी डेटा डेवलपर या किसी और तक पहुँच सके। नीचे जो भी बताया गया है, वह सब कुछ सिर्फ़ आपके अपने डिवाइस पर होता है।

ऐप खुद आपके डिवाइस पर लोकली क्या एक्सेस/स्टोर कर सकती है: आपके प्रॉम्प्ट और AI के जवाब (सिर्फ़ चैट करते समय मेमोरी में प्रोसेस होते हैं), चैट हिस्ट्री, आपके चुने हुए GGUF मॉडल फ़ाइलें, और "रिस्पॉन्स रिपोर्ट करें" से बनाई गई कोई भी रिपोर्ट - यह सब इस ऐप की अपनी लोकल स्टोरेज के अंदर ही रहता है।

प्रॉम्प्ट और AI के जवाब: आप जो भी टाइप करते हैं, और AI मॉडल जो भी जवाब जनरेट करता है, सब कुछ पूरी तरह आपके डिवाइस पर, आपके चुने हुए GGUF मॉडल द्वारा प्रोसेस होता है। आप जो भी टाइप या प्राप्त करते हैं, वह इस ऐप द्वारा कहीं भी ट्रांसमिट नहीं होता।

चैट हिस्ट्री: आपके डिवाइस पर लोकली स्टोर होती है (इस ऐप की प्राइवेट स्टोरेज के अंदर) ताकि आप पुरानी बातचीत देख सकें। जब आप उस चैट को यहाँ से डिलीट करते हैं या ऐप अनइंस्टॉल करते हैं तो वह डिलीट हो जाती है। चैट हिस्ट्री फ़ाइल Android Keystore के अंदर जनरेट और होल्ड होने वाली की (key) से एन्क्रिप्ट होती है (जो डिवाइस सपोर्ट करते हैं उनमें हार्डवेयर-बैक्ड), जिसका डिज़ाइन ऐसा है कि अगर फ़ाइल कभी डिवाइस से निकाली भी जाए, तो उस key के बिना पढ़ी न जा सके। किसी भी सिक्योरिटी इम्प्लीमेंटेशन की तरह, हम यह वादा नहीं कर सकते कि यह हर स्थिति में (जैसे किसी कॉम्प्रोमाइज़्ड या रूटेड डिवाइस पर) पूरी तरह अभेद्य है, और हम पूर्ण सुरक्षा की कोई वारंटी नहीं देते।

मॉडल फ़ाइलें: आप खुद अपने डिवाइस की स्टोरेज से एक .gguf मॉडल फ़ाइल Android के सिस्टम फ़ाइल पिकर से चुनते हैं; यह ऐप कभी मॉडल को इंटरनेट से फ़ेच, वेरिफ़ाई, या अपडेट नहीं करती। चुनी गई मॉडल फ़ाइलें इस ऐप की प्राइवेट स्टोरेज में लोकली सेव होती हैं और जब आप उन्हें Models स्क्रीन से डिलीट करते हैं या ऐप अनइंस्टॉल करते हैं तो हट जाती हैं।

AI रिस्पॉन्स रिपोर्ट्स: अगर आप किसी AI जवाब पर "रिस्पॉन्स रिपोर्ट करें" इस्तेमाल करते हैं, तो वह रिपोर्ट (आपका चुना गया कारण, वैकल्पिक टिप्पणी, AI रिस्पॉन्स टेक्स्ट, और मॉडल का नाम) सिर्फ़ इस ऐप की लोकल, प्राइवेट स्टोरेज में सेव होती है, चैट हिस्ट्री की तरह ही एन्क्रिप्टेड। यह डेवलपर या किसी और को अपने आप नहीं भेजी जाती। अगर आप रिपोर्ट देखने के बाद "शेयर करें (ईमेल, आदि)" चुनते हैं, तो Android की अपनी सिस्टम शेयर शीट खुलती है, और आप खुद तय करते हैं कि किस ऐप या कॉन्टैक्ट को भेजनी है - इस ट्रांसमिशन में इस ऐप का काम सिर्फ़ इतना है कि वह टेक्स्ट उस शेयर शीट को दे देता है जो आपने खुद खोली। आपका असली प्रॉम्प्ट शेयर की गई रिपोर्ट में सिर्फ़ तभी शामिल होता है जब आप साफ़ तौर पर "मेरा असली मैसेज भी शामिल करें" चेकबॉक्स टिक करते हैं - यह डिफ़ॉल्ट रूप से कभी शामिल नहीं होता।

बैकअप: इस ऐप की कॉन्फ़िगरेशन में android:allowBackup="false" सेट है, और इसके अलावा, चैट हिस्ट्री, मॉडल फ़ाइलें, और रिपोर्ट्स सब Android के डेडिकेटेड नो-बैकअप स्टोरेज एरिया (getNoBackupFilesDir) में स्टोर होते हैं। ये दोनों Android के स्टैंडर्ड, डॉक्यूमेंटेड तरीके हैं डेटा को क्लाउड ऑटो बैकअप और डिवाइस-टू-डिवाइस ट्रांसफ़र से बाहर रखने के, और यह ऐप ऐसे ही काम करने के लिए डिज़ाइन किया गया है। फिर भी, अलग-अलग मैन्युफैक्चरर, OS वर्शन, और कस्टम Android बिल्ड्स में व्यवहार अलग हो सकता है जो हमारे नियंत्रण से बाहर है, इसलिए हम हर संभव स्थिति में यह नतीजा गारंटी नहीं कर सकते।

परमिशन: इस ऐप में कोई इंटरनेट परमिशन और कोई स्टोरेज परमिशन नहीं है। मॉडल फ़ाइलें Android के सिस्टम फ़ाइल पिकर से चुनी जाती हैं, जो सिर्फ़ उस एक फ़ाइल तक ही एक्सेस देता है जो आप चुनते हैं।

अपना डेटा डिलीट करना: Settings में एक "सारा डेटा डिलीट करें" बटन है जो एक ही एक्शन में इस डिवाइस की ऐप स्टोरेज से हर मॉडल फ़ाइल, सारी चैट हिस्ट्री, और सारी सेव्ड रिपोर्ट्स परमानेंटली डिलीट करने के लिए डिज़ाइन किया गया है, और ऐप के अंदर इसे वापस नहीं लाया जा सकता। आप चीज़ें अलग-अलग भी डिलीट कर सकते हैं - Models स्क्रीन से एक मॉडल, Chat History से एक चैट, या बस ऐप अनइंस्टॉल करके, जिससे ऐप की स्टोरेज हट जाती है। हम Android के स्टैंडर्ड फ़ाइल-डिलीशन मैकेनिज़्म पर निर्भर करते हैं; हम इस बारे में कोई दावा नहीं करते कि डेटा किसी विशेष तकनीकी तरीके से अंडरलाइंग स्टोरेज हार्डवेयर से रिकवर किया जा सकता है या नहीं, जो ऐप और ऑपरेटिंग सिस्टम के नियंत्रण से बाहर है।

डिस्क्लेमर: यह ऐप, इसके AI-जनरेटेड जवाब, और इसकी सुविधाएँ "जैसी हैं" और "जैसी उपलब्ध हैं" के आधार पर दी जाती हैं, बिना किसी तरह की वारंटी के, चाहे स्पष्ट हो या अंतर्निहित, जिसमें सटीकता, विश्वसनीयता, किसी खास मकसद के लिए उपयुक्तता, या निर्बाध उपलब्धता शामिल है लेकिन इन्हीं तक सीमित नहीं है। यह ऐप ऊपर बताई गई प्राइवेसी और सिक्योरिटी प्रैक्टिसेज़ के साथ डिज़ाइन किया गया है, फिर भी हम यह गारंटी नहीं देते कि कोई खास सिक्योरिटी, प्राइवेसी, बैकअप-एक्सक्लूज़न, या डेटा-डिलीशन नतीजा हर स्थिति, डिवाइस, या Android वर्शन में वैसा ही रहेगा। आप इस ऐप का, और इससे जनरेट हुए किसी भी कंटेंट का, इस्तेमाल अपने खुद के विवेक और जोखिम पर करते हैं। लागू कानून द्वारा अनुमत अधिकतम सीमा तक, डेवलपर इस ऐप के इस्तेमाल से उत्पन्न किसी भी नुकसान, हानि, या समस्या के लिए ज़िम्मेदारी से इनकार करता है।

बच्चे: यह ऐप 13 साल से कम उम्र के बच्चों के लिए नहीं बनाया गया है।

डेवलपर: Ram Singh Yadav
संपर्क: sys7userui@gmail.com
"""

        const val LICENSES_EN = """
This app uses the following open source components:

- llama-android (dev.ffmpegkit-maintained:llama-android) - MIT License
  Copyright (c) 2026 Jokobee
  https://github.com/ffmpegkit-maintained/llama-android
  Prebuilt Android AAR providing the on-device GGUF inference API this app calls
  (Llama.loadModel / Llama.complete / Llama.releaseModel). This artifact bundles
  the upstream llama.cpp native library inside it - see the next entry.

- llama.cpp - MIT License
  Copyright (c) 2023 Georgi Gerganov
  https://github.com/ggerganov/llama.cpp
  The native inference engine bundled inside the llama-android AAR above; this
  app does not link it directly, but its notices are included here since its
  compiled code ships inside this app.

- Android Jetpack (Core, Activity, Lifecycle, Compose) - Apache License 2.0
  Copyright (c) The Android Open Source Project

- Kotlin Standard Library and Coroutines - Apache License 2.0
  Copyright (c) JetBrains s.r.o.

- Material Components / Material 3 - Apache License 2.0
  Copyright (c) Google LLC

- org.jetbrains:markdown - Apache License 2.0
  Copyright (c) JetBrains s.r.o.
  https://github.com/JetBrains/markdown
  Used to parse AI response text as CommonMark/GFM Markdown (headings, bold,
  italic, lists, inline code, autolinked URLs) for display in the chat.

Note: this list reflects the direct Maven dependency actually declared in this
app's build configuration and its documented bundled native library. If that
dependency is ever changed, this section must be reviewed and updated to match.

Model weights are NOT bundled with this app. Each model you import has its
own publisher and its own license, which may differ from model to model. You
are responsible for reviewing and complying with the license of any model you
import.

Full license texts:
Apache 2.0 - https://www.apache.org/licenses/LICENSE-2.0

MIT - https://opensource.org/licenses/MIT
"""

        const val LICENSES_HI = """
यह ऐप इन ओपन सोर्स कॉम्पोनेंट्स का इस्तेमाल करता है:

- llama-android (dev.ffmpegkit-maintained:llama-android) - MIT License
  Copyright (c) 2026 Jokobee
  https://github.com/ffmpegkit-maintained/llama-android
  यह प्रीबिल्ट Android AAR वही ऑन-डिवाइस GGUF इन्फरेंस API देता है जो यह ऐप
  कॉल करती है (Llama.loadModel / Llama.complete / Llama.releaseModel)। इसमें
  अपस्ट्रीम llama.cpp नेटिव लाइब्रेरी बंडल है - नीचे वाली एंट्री देखें।

- llama.cpp - MIT License
  Copyright (c) 2023 Georgi Gerganov
  https://github.com/ggerganov/llama.cpp
  यह नेटिव इन्फरेंस इंजन ऊपर वाले llama-android AAR के अंदर बंडल है; यह ऐप
  इसे डायरेक्टली लिंक नहीं करती, लेकिन इसके नोटिस यहाँ शामिल किए गए हैं
  क्योंकि इसका कंपाइल्ड कोड इस ऐप के अंदर शिप होता है।

- Android Jetpack (Core, Activity, Lifecycle, Compose) - Apache License 2.0
  Copyright (c) The Android Open Source Project

- Kotlin Standard Library और Coroutines - Apache License 2.0
  Copyright (c) JetBrains s.r.o.

- Material Components / Material 3 - Apache License 2.0
  Copyright (c) Google LLC

- org.jetbrains:markdown - Apache License 2.0
  Copyright (c) JetBrains s.r.o.
  https://github.com/JetBrains/markdown
  AI response text ko CommonMark/GFM Markdown ki tarah parse karne ke liye
  use hoti hai (headings, bold, italic, lists, inline code, autolinked URLs)
  taaki chat me sahi se dikhaya ja sake.

नोट: यह लिस्ट इस ऐप के बिल्ड कॉन्फ़िगरेशन में असल में डिक्लेयर की गई डायरेक्ट
Maven डिपेंडेंसी और उसकी डॉक्यूमेंटेड बंडल्ड नेटिव लाइब्रेरी को दर्शाती है।
अगर वह डिपेंडेंसी कभी बदली जाए, तो यह सेक्शन रिव्यू करके अपडेट करना ज़रूरी है।

मॉडल वेट्स इस ऐप के साथ बंडल नहीं होते। आपके इंपोर्ट किए गए हर मॉडल का अपना
पब्लिशर और अपना लाइसेंस होता है, जो मॉडल से मॉडल अलग हो सकता है। आप जो भी
मॉडल इंपोर्ट करते हैं, उसका लाइसेंस रिव्यू करना और उसे फॉलो करना आपकी
ज़िम्मेदारी है।

पूरे लाइसेंस टेक्स्ट:
Apache 2.0 - https://www.apache.org/licenses/LICENSE-2.0

MIT - https://opensource.org/licenses/MIT
"""
    }
}