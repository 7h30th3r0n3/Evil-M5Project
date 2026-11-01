package com.evil.relay

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import androidx.core.content.ContextCompat
import com.google.android.material.textfield.TextInputEditText
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/*
 * EvilRelay - NFC relay app, two roles (Wi-Fi/TCP transport):
 *
 *  Reader   : this phone READS the real card (IsoDep) and relays APDUs over
 *             Wi-Fi/TCP to the emulator. The emulator can be an Evil-Cardputer,
 *             another phone in Emulator mode, or the ESP32 bridge in front of a
 *             Flipper running the EvilRelay FAP (the Flipper does ISO-DEP).
 *  Emulator : this phone EMULATES the card to a terminal via HCE and forwards the
 *             terminal's APDUs over Wi-Fi/TCP to a Reader (phone or Cardputer).
 *
 * The emulator is the TCP server (port 5566); the reader is the client. When the
 * reader talks to the ESP32+Flipper, the ESP32 is the TCP server (192.168.4.1).
 *
 * HCE limit (Emulator mode only): Android sets its own random UID and does not
 * expose ATS/SAK, so a phone emulator presents Android's identity, not the real
 * card's. RRP-strict terminals reject it — that is why the Flipper is the real
 * emulator. The Reader (Wi-Fi) path is full ISO-DEP and carries the real ATS.
 */
class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var nfc: NfcAdapter? = null
    private lateinit var statusText: TextView
    private lateinit var statusDot: android.view.View
    private lateinit var ipInput: TextInputEditText
    private lateinit var cardUid: TextView
    private lateinit var apduCount: TextView
    private lateinit var logText: TextView
    private lateinit var roleGroup: RadioGroup
    private lateinit var keepAwake: SwitchCompat
    private lateinit var subtitle: TextView
    private lateinit var relayPanel: android.view.View
    private lateinit var emvPanel: android.view.View
    private lateinit var wifiBox: android.view.View
    private lateinit var logLabel: TextView
    private lateinit var emvScheme: TextView
    private lateinit var emvPan: TextView
    private lateinit var emvName: TextView
    private lateinit var emvExp: TextView

    private val port = 5566
    @Volatile private var emulator = false
    @Volatile private var serverRunning = false
    private var server: ServerSocket? = null

    private enum class Mode { READER, EMULATOR, EMV_INFO }
    @Volatile private var mode = Mode.READER

    // Log de-dup: onResume() runs checkWifi()/applyRole() on every resume, which used to
    // reprint the same lines in a loop. Show the "not on WiFi" warning and the role banner
    // only once (until the underlying state actually changes).
    private var wifiWarnShown = false
    private var lastRoleLogged: Mode? = null

    // Reader link: in Reader mode the app holds a persistent TCP connection to the emulator
    // (opened as soon as the role is active, not per-card) so the emulator sees "app open" before
    // any card, and a card swap re-uses the same link (new IDENT re-arms the emulator).
    @Volatile private var readerRunning = false
    @Volatile private var pendingTag: Tag? = null
    private var readerThread: Thread? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusText = findViewById(R.id.statusText)
        statusDot = findViewById(R.id.statusDot)
        ipInput = findViewById(R.id.ipInput)
        cardUid = findViewById(R.id.cardUid)
        apduCount = findViewById(R.id.apduCount)
        logText = findViewById(R.id.logText)
        roleGroup = findViewById(R.id.roleGroup)
        keepAwake = findViewById(R.id.keepAwake)
        subtitle = findViewById(R.id.subtitle)
        relayPanel = findViewById(R.id.relayPanel)
        emvPanel = findViewById(R.id.emvPanel)
        wifiBox = findViewById(R.id.wifiBox)
        logLabel = findViewById(R.id.logLabel)
        emvScheme = findViewById(R.id.emvScheme)
        emvPan = findViewById(R.id.emvPan)
        emvName = findViewById(R.id.emvName)
        emvExp = findViewById(R.id.emvExp)

        // Keep the screen awake while relaying (default on): if the phone locks, NFC
        // and the TCP relay get interrupted mid-transaction. Only applies while the
        // app is in the foreground (no wake-lock permission, no background drain).
        val prefs = getSharedPreferences("evilrelay", Context.MODE_PRIVATE)
        keepAwake.isChecked = prefs.getBoolean("keep_awake", true)
        applyKeepAwake(keepAwake.isChecked)
        keepAwake.setOnCheckedChangeListener { _, on ->
            applyKeepAwake(on)
            prefs.edit().putBoolean("keep_awake", on).apply()
        }

        Relay.logSink = { s -> logln(s) }
        nfc = NfcAdapter.getDefaultAdapter(this)

        roleGroup.setOnCheckedChangeListener { _, id ->
            mode = when (id) {
                R.id.roleEmulator -> Mode.EMULATOR
                R.id.roleEmvInfo -> Mode.EMV_INFO
                else -> Mode.READER
            }
            emulator = (mode == Mode.EMULATOR)
            applyRole()
        }

        if (nfc == null) {
            setStatus("No NFC on this phone", R.color.err)
        }

        handleDeepLink(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLink(intent)
    }

    // Deep link entry: evilrelay://relay[?ip=...][&role=reader|emulator]
    // Opens the app straight into a relay role (default Reader @ 192.168.4.1, i.e. the
    // Cardputer/ESP32 emulator). Triggered by a QR code or link, not the captive portal
    // WebView (which Android sandboxes and will not let launch an app).
    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme != "evilrelay") return
        val ip = data.getQueryParameter("ip")?.trim()
        if (!ip.isNullOrEmpty()) ipInput.setText(ip)
        val role = (data.getQueryParameter("role") ?: data.host ?: "reader").lowercase()
        mode = when {
            role.contains("emul") -> Mode.EMULATOR
            role.contains("emv")  -> Mode.EMV_INFO
            else -> Mode.READER
        }
        emulator = (mode == Mode.EMULATOR)
        roleGroup.check(when (mode) {
            Mode.EMULATOR -> R.id.roleEmulator
            Mode.EMV_INFO -> R.id.roleEmvInfo
            else -> R.id.roleReader
        })
        applyRole()
        logln("Deep link: $mode mode" + (if (!ip.isNullOrEmpty()) " -> $ip" else ""))
    }

    override fun onResume() {
        super.onResume()
        checkNfcEnabled()
        checkWifi()
        applyRole()
    }

    override fun onPause() {
        super.onPause()
        nfc?.disableReaderMode(this)
        stopReaderLink()
        stopServer()
    }

    private fun applyKeepAwake(on: Boolean) {
        if (on) window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    // ---- role switching ----
    private fun applyRole() {
        nfc?.disableReaderMode(this)
        stopServer()
        apduCount(0)
        updateUiForMode()
        when (mode) {
            Mode.EMULATOR -> {
                stopReaderLink()   // leaving reader mode -> drop its persistent link
                startServer()
                val ip = localIp()
                setStatus("Emulator - waiting reader", R.color.warn)
                cardUid.text = "Listen $ip:$port"
                if (lastRoleLogged != Mode.EMULATOR) {
                    logln("Emulator (HCE) mode. Reader connects to $ip:$port. Then tap the terminal.")
                    lastRoleLogged = Mode.EMULATOR
                }
            }
            Mode.READER -> {
                enableReader()
                setStatus("Reader - place a card", R.color.warn)
                cardUid.text = "-"
                if (lastRoleLogged != Mode.READER) {
                    logln("Reader mode (Wi-Fi). Target emulator IP: " + hostIp())
                    lastRoleLogged = Mode.READER
                }
            }
            Mode.EMV_INFO -> {
                stopReaderLink()        // read-only, no network
                enableNfcReader()       // NFC reader only (no TCP link)
                setStatus("EMV reader - tap a card", R.color.warn)
                if (lastRoleLogged != Mode.EMV_INFO) {
                    logln("EMV reader mode (read-only). Tap a card to read its public data.")
                    lastRoleLogged = Mode.EMV_INFO
                }
            }
        }
    }

    // Show/hide the panels and adapt the labels to the current mode (additive; relay UI untouched).
    private fun updateUiForMode() {
        val emv = (mode == Mode.EMV_INFO)
        emvPanel.visibility = if (emv) android.view.View.VISIBLE else android.view.View.GONE
        relayPanel.visibility = if (emv) android.view.View.GONE else android.view.View.VISIBLE
        wifiBox.visibility = if (emv) android.view.View.GONE else android.view.View.VISIBLE
        logLabel.text = if (emv) "EMV DETAILS" else "LOG"
        subtitle.text = when (mode) {
            Mode.EMULATOR -> "NFC relay - emulator side"
            Mode.EMV_INFO -> "EMV reader - read-only"
            else -> "NFC relay - reader side"
        }
    }

    // Enable the NFC reader (no network). Used by both Reader relay and EMV Info modes.
    private fun enableNfcReader() {
        // 1 s presence check: detect card removal / swap quickly so the UID refreshes and a
        // "card removed" state shows, instead of holding the old tag for 5 s. EMV APDUs flow
        // sub-second, so this does not cut into an active transaction.
        val opts = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000) }
        nfc?.enableReaderMode(
            this, this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, opts
        )
    }

    private fun enableReader() {
        enableNfcReader()
        startReaderLink()
    }

    // ============================ READER / EMV ============================
    // Reader relay: hand the tag to the persistent link thread. EMV Info: read it locally.
    override fun onTagDiscovered(tag: Tag) {
        when (mode) {
            Mode.READER -> pendingTag = tag
            Mode.EMV_INFO -> readEmv(tag)
            else -> {}
        }
    }

    // Read one card's EMV data locally and display it (read-only, no relay / no network).
    private fun readEmv(tag: Tag) {
        val iso = IsoDep.get(tag) ?: run { setStatus("Card not ISO-DEP", R.color.err); return }
        try {
            iso.connect()
            setStatus("Reading EMV...", R.color.cyan)
            showEmv(Emv.readCard(iso))
        } catch (e: Exception) {
            setStatus("Read error", R.color.err); logln("emv err: ${e.message}")
        } finally { try { iso.close() } catch (_: Exception) {} }
    }

    private fun showEmv(info: Emv.Info) {
        runOnUiThread {
            emvScheme.text = if (info.scheme.isNotEmpty()) info.scheme else "EMV"
            emvPan.text = if (info.pan.isNotEmpty()) info.pan.chunked(4).joinToString("  ") else "----  ----  ----  ----"
            emvName.text = if (info.cardholder.isNotEmpty()) info.cardholder else "-"
            emvExp.text = if (info.expiry.isNotEmpty()) info.expiry else "--/--"
            logText.text = ""
        }
        logln(Emv.format(info))
        setStatus(if (info.ok) "EMV read OK" else "No EMV data", if (info.ok) R.color.ok else R.color.warn)
    }

    private fun startReaderLink() {
        if (readerRunning) return
        readerRunning = true
        readerThread = thread(name = "reader-link") {
            while (readerRunning) {
                val host = hostIp()
                try {
                    Socket(host, port).use { sock ->
                        sock.tcpNoDelay = true
                        sock.soTimeout = 700   // wake when idle so card removal is noticed
                        setStatus("Linked to $host - tap a card", R.color.ok)
                        logln("Linked to emulator $host - tap a card")
                        runOnUiThread { cardUid.text = "-" }
                        while (readerRunning && !sock.isClosed) {
                            val tag = pendingTag
                            if (tag == null) { try { Thread.sleep(50) } catch (_: Exception) {}; continue }
                            pendingTag = null
                            serveCard(tag, sock)   // IDENT + relay until the card is removed (throws if link dies)
                            if (readerRunning && !sock.isClosed) {
                                setStatus("Linked - tap a card", R.color.ok)
                                runOnUiThread { cardUid.text = "-" }
                            }
                        }
                    }
                } catch (e: Exception) {
                    setStatus("No emulator at ${hostIp()} - retry", R.color.warn)
                    logln("link err: ${e.message}  (WiFi joined? peer IP?)")
                }
                if (readerRunning) try { Thread.sleep(800) } catch (_: Exception) {}   // reconnect backoff
            }
        }
    }

    private fun stopReaderLink() {
        readerRunning = false
        pendingTag = null
        readerThread = null   // thread exits on readerRunning=false; use{} closes the socket
    }

    // Relay one card over the already-open link. Returns when the card is removed (keep the socket,
    // wait for the next card). Throws on a dead socket so the link thread reconnects.
    private fun serveCard(tag: Tag, sock: Socket) {
        val iso = IsoDep.get(tag) ?: run { setStatus("Card not ISO-DEP", R.color.err); return }
        val nfca = NfcA.get(tag)
        try {
            iso.timeout = 5000
            iso.connect()
            val uid = tag.id ?: ByteArray(0)
            val atqa = nfca?.atqa ?: byteArrayOf(0x04, 0x00)
            val sak = (nfca?.sak?.toInt() ?: 0x20)
            val hist = iso.historicalBytes ?: ByteArray(0)
            val ats = buildAts(hist)
            runOnUiThread { cardUid.text = "UID ${Relay.hex(uid)}  SAK %02X".format(sak) }
            val out = sock.getOutputStream(); val inp = sock.getInputStream()
            val ident = ArrayList<Byte>()
            ident.add(uid.size.toByte()); uid.forEach { ident.add(it) }
            ident.add(atqa.getOrElse(0) { 0 }); ident.add(atqa.getOrElse(1) { 0 })
            ident.add(sak.toByte())
            ident.add(ats.size.toByte()); ats.forEach { ident.add(it) }
            Relay.sendFrame(out, 1, 0, ident.toByteArray())   // new identity -> emulator re-arms
            setStatus("Relay active", R.color.ok)
            logln("Card UID ${Relay.hex(uid)} - relay active")
            var count = 0
            // Blocking read = zero added latency during a transaction; on idle timeout re-check the
            // card and break if it was removed (iso.isConnected flips ~1s after the presence check).
            while (readerRunning && iso.isConnected && !sock.isClosed) {
                val f = try { Relay.readFrame(inp) }
                        catch (te: java.net.SocketTimeoutException) { if (!iso.isConnected) break else continue }
                        ?: throw java.io.IOException("emulator closed")   // socket dead -> reconnect
                if (f.type.toInt() and 0xFF == 2) {
                    val resp = try { iso.transceive(f.payload) }
                    catch (e: Exception) { setStatus("Card lost - re-tap", R.color.err); logln("Card lost mid-APDU"); break }
                    Relay.sendFrame(out, 3, f.seq.toInt(), resp)
                    count++; val c = count
                    runOnUiThread { apduCount.text = c.toString() }
                    if (count <= 16) logln("APDU #$count  ${f.payload.size}B -> ${resp.size}B")
                }
            }
            logln("Card session ended ($count APDU)")
            if (count > 0) setStatus("Card done - $count APDU", R.color.cyan)
        } finally {
            try { iso.close() } catch (_: Exception) {}
        }
    }

    // ============================ EMULATOR ============================
    private fun startServer() {
        serverRunning = true
        thread(name = "relay-srv") {
            try {
                val ss = ServerSocket(port); server = ss; ss.soTimeout = 0
                while (serverRunning) {
                    val c = try { ss.accept() } catch (e: Exception) { break }
                    try {
                        c.tcpNoDelay = true
                        val f = Relay.readFrame(c.getInputStream())   // IDENT (card identity; HCE uses Android's own UID)
                        Relay.readerSocket = c
                        if (f != null && f.type.toInt() and 0xFF == 1)
                            logln("Reader linked (card IDENT ${f.payload.size}B) - tap the terminal now")
                        else logln("Reader linked - tap the terminal now")
                        setStatus("Emulator ready - tap terminal", R.color.ok)
                    } catch (e: Exception) {
                        logln("reader link err: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                logln("server err: ${e.message}")
            }
        }
    }

    private fun stopServer() {
        serverRunning = false
        try { server?.close() } catch (_: Exception) {}
        server = null
        try { Relay.readerSocket?.close() } catch (_: Exception) {}
        Relay.readerSocket = null
    }

    // ---- checks ----
    private fun checkNfcEnabled() {
        val a = nfc ?: return
        if (!a.isEnabled) {
            AlertDialog.Builder(this)
                .setTitle("NFC is off")
                .setMessage("Enable NFC to relay. Open NFC settings?")
                .setPositiveButton("Open settings") { _, _ ->
                    try { startActivity(Intent(Settings.ACTION_NFC_SETTINGS)) }
                    catch (e: Exception) { startActivity(Intent(Settings.ACTION_SETTINGS)) }
                }
                .setNegativeButton("Later", null)
                .show()
            setStatus("NFC is off", R.color.err)
        }
    }

    private fun checkWifi(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val net = cm.activeNetwork
        val cap = cm.getNetworkCapabilities(net)
        val wifi = cap?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        if (!wifi && mode != Mode.EMV_INFO) {
            if (!wifiWarnShown) { logln("Warning: not on WiFi. Join the relay WiFi / hotspot."); wifiWarnShown = true }
        } else wifiWarnShown = false   // back on WiFi (or EMV mode) -> allow one fresh warning later
        return wifi
    }

    private fun localIp(): String {
        try {
            for (ni in NetworkInterface.getNetworkInterfaces()) {
                if (!ni.isUp || ni.isLoopback) continue
                for (addr in ni.inetAddresses) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) return addr.hostAddress ?: "?"
                }
            }
        } catch (_: Exception) {}
        return "?"
    }

    private fun hostIp(): String =
        ipInput.text?.toString()?.trim().let { if (it.isNullOrEmpty()) "192.168.4.1" else it }

    // ATS wrapping the real historical bytes (reader mode only; Android does not expose raw ATS).
    // TL,T0=0x78(TA1|TB1|TC1,FSCI=8),TA1=0x80,TB1=0xE0(FWI=14),TC1=0x00, then historical bytes.
    private fun buildAts(hist: ByteArray): ByteArray {
        val body = byteArrayOf(0x78.toByte(), 0x80.toByte(), 0xE0.toByte(), 0x00) + hist
        return byteArrayOf((1 + body.size).toByte()) + body
    }

    private fun apduCount(n: Int) { Relay.apduCount = n; runOnUiThread { apduCount.text = n.toString() } }

    private fun setStatus(text: String, colorRes: Int) = runOnUiThread {
        statusText.text = text
        statusDot.backgroundTintList = ColorStateList.valueOf(ContextCompat.getColor(this, colorRes))
    }

    private fun logln(s: String) = runOnUiThread { logText.append(s + "\n") }
}
