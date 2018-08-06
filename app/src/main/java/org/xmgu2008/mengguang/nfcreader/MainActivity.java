package org.xmgu2008.mengguang.nfcreader;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.io.IOException;
import java.math.BigInteger;

public class MainActivity extends AppCompatActivity implements Runnable {

    private final byte[][] mKeys;
    private final String[][] mTechLists;
    private NfcAdapter mAdapter;
    private PendingIntent mPendingIntent;
    private IntentFilter[] mFilters;
    private Tag mTag;

    public MainActivity()
    {
        // A keys, read-only
        mKeys = new byte[][]{
                {(byte) 0x7A, (byte) 0x97, (byte) 0xD8, (byte) 0xD5, (byte) 0xC2, (byte) 0x42}
        };

        // Tech list for all desired tags
        mTechLists = new String[][] { new String[] { NfcA.class.getName() }};
    }

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        NfcManager mManager = (NfcManager) getSystemService(NFC_SERVICE);
        mAdapter = mManager.getDefaultAdapter();
        if (mAdapter != null)
            eatToast("Place tag on phone");

        // PendingIntent object containing details of the scanned tag
        mPendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        IntentFilter mNdef = null;
        try
        {
            // Accept all MIME types
            mNdef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
            mNdef.addDataType("*/*");
        }
        catch (IntentFilter.MalformedMimeTypeException e)
        {
            eatToast(String.format("MalformedMimeTypeException: %s", e.getLocalizedMessage()));
            e.printStackTrace(); // to logcat
        }

        mFilters = new IntentFilter[] { mNdef, new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED) };
    }

    @Override
    public void onResume()
    {
        super.onResume();

        // Make sure we have an adapter, otherwise this fails
        if (mAdapter != null)
            mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters, mTechLists);
    }

    @Override
    public void onPause()
    {
        super.onPause();

        // Make sure we have an adapter, otherwise this fails
        if (mAdapter != null)
            mAdapter.disableForegroundDispatch(this);
    }

    @Override
    public void onNewIntent(Intent intent)
    {
        // Make sure intent is tag discovery; ignore the rest
        if (!NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction()))
            return;

        // Retrieve extended data from the intent
        mTag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if(mTag == null) return;

        eatToast(String.format("Found tag (%s)",
                Utils.getHexString(intent.getByteArrayExtra(NfcAdapter.EXTRA_ID))));
        Log.e("NFC","Starting thread.");
        // Start new thread
        Thread aThread = new Thread(this);
        aThread.start();
    }

    @Override
    public void run()
    {
        try
        {
            MifareClassic mMfc = MifareClassic.get(mTag);
            Log.e("NFC","Now in thread.");
            // Make sure tag is a MIFARE Classic card and 4K in size
            if (mMfc.getType() != MifareClassic.TYPE_CLASSIC) return;
            if (mMfc.getSize() != MifareClassic.SIZE_1K) return;

            // "Connect" to tag
            mMfc.connect();

            // Check if we're connected, otherwise sadface
            if (!mMfc.isConnected())
            {
                eatToast("Unable to connect to tag. Sadface.");
                return;
            }

            StringBuilder bits = new StringBuilder();

            eatToast("Reading");

            // Loop through all sectors
            for (int sector = 0; sector < (mMfc.getSectorCount()); ++sector)
            {
                boolean authenticated = false;

                // Try authenticate with all keys
                // FIXME: overhead
                for (byte[] key : mKeys) {
                    if (mMfc.authenticateSectorWithKeyA(sector, key)) {
                        authenticated = true;
                        break;
                    }
                    if (mMfc.authenticateSectorWithKeyB(sector, key)) {
                        authenticated = true;
                        break;
                    }
                }

                // Authentication to sector failed, invalid key(s)
                if (!authenticated) continue;
                Log.e("NFC","Auth success.");

                // Read all blocks in sector
                for (int block = 0; (block < mMfc.getBlockCountInSector(sector)); ++block)
                {
                    // Get block number for sector + block
                    int blockIndex = (mMfc.sectorToBlock(sector) + block);

                    try
                    {
                        // Read block data from block index
                        byte[] data = mMfc.readBlock(blockIndex);
                        System.out.printf("block: %02d : %s \n ",blockIndex,Utils.getHexString(data));
                        // Create a string of bits from block data and fix endianness
                        // http://en.wikipedia.org/wiki/Endianness
                        String temp = Utils.getBinaryString(data);

                        for (int x = 0; x < temp.length(); x += 8)
                            bits.append(new StringBuilder(temp.substring(x, x+8)).reverse().toString());
                    }
                    catch (IOException e)
                    {
                        eatToast(String.format("Exception: %s", e.getLocalizedMessage()));
                    }
                }
            }

            // print each block for great visualization (128 bits/16 bytes)
            //int block = 0;
            //for (String s : bits.toString().replaceAll("(.{128})", "$1|").split("\\|"))
            //    System.out.println(String.format("Block %02d : %s", block++, s));


            // Cleaning lady
            mMfc.close();

            // Done, bzzzz
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(VibrationEffect.createOneShot(100,VibrationEffect.DEFAULT_AMPLITUDE));

            eatToast("Done");
        }
        catch (IOException e)
        {
            eatToast(String.format("Exception: %s", e.getLocalizedMessage()));
            e.printStackTrace(); // to logcat
        }
    }

    /**
     * Display a "Toast" message
     * @param message The message of course
     */
    private void eatToast(final String message)
    {
        MainActivity.this.runOnUiThread(new Runnable()
        {
            @Override
            public void run()
            {
                Toast mToast = Toast.makeText(MainActivity.this, message, Toast.LENGTH_LONG);
                mToast.show();
            }
        });
    }
}

class Utils
{
    /**
     * Get hex string from byte array
     * @param buf Byte buffer
     * @return Hex string
     */
    public static String getHexString(byte[] buf)
    {
        StringBuilder sb = new StringBuilder();

        for (byte b : buf)
            sb.append(String.format("%02X ", b));

        return sb.toString().trim();
    }

    /**
     * Get byte array from binary string
     * @param s Binary string
     * @return Byte array
     */
    public static byte[] binaryStringToByteArray(String s)
    {
        byte[] ret = new byte[(s.length()+8-1) / 8];

        BigInteger bigint = new BigInteger(s, 2);
        byte[] bigintbytes = bigint.toByteArray();

        if (bigintbytes.length > ret.length) {
            //get rid of preceding 0
            for (int i = 0; i < ret.length; i++) {
                ret[i] = bigintbytes[i+1];
            }
        }
        else {
            ret = bigintbytes;
        }
        return ret;
    }

    /**
     * Get binary string from byte array
     * @param input Byte array
     * @return Binary string
     */
    public static String getBinaryString(byte[] input)
    {
        StringBuilder sb = new StringBuilder();

        for (byte c : input)
        {
            for (int n = 128; n > 0; n >>= 1)
            {
                String res = ((c & n) == 0) ? "0" : "1";
                sb.append(res);
            }
        }

        return sb.toString();
    }
}