package org.bitcoinj.tools;

/**
 * Created by Sergio on 12/04/2017.
 */


import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.store.*;
import org.bitcoinj.utils.BlockFileLoader;
import com.google.common.base.Preconditions;
import org.bitcoinj.wallet.DefaultRiskAnalysis;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static com.google.common.base.Preconditions.checkArgument;
import static org.bitcoinj.script.ScriptOpCodes.*;
import static org.bitcoinj.script.ScriptOpCodes.OP_1;
import static org.bitcoinj.script.ScriptOpCodes.OP_1NEGATE;

public class BlockAnalysis {
    private FileInputStream currentFileStream = null;
    private Block nextBlock = null;

    public Block importBlock(NetworkParameters params, String fileName) {
        try {
            currentFileStream = new FileInputStream(fileName);
            long size = new File(fileName).length();

            try {
                //deserialize without msg header
                byte[] bytes = new byte[(int) size];
                currentFileStream.read(bytes, 0, (int) size);
                /*
                nextBlock = params.getDefaultSerializer().makeBlock(bytes);
                */
                // Deserialize with msg headers

                nextBlock = (Block) params.getDefaultSerializer().deserialize(ByteBuffer.wrap(bytes));
                return nextBlock;
            } catch (ProtocolException e) {

            }
        } catch (FileNotFoundException e) {
            currentFileStream = null;

        } catch (IOException e) {
            currentFileStream = null;
        }
        return null;
    }

    public void exportBlock(NetworkParameters params, Block block, String fileName) {
        FileOutputStream fop = null;
        File file;

        try {
            file = new File(fileName);
            fop = new FileOutputStream(file);

            // if file doesnt exists, then create it
            if (!file.exists()) {
                file.createNewFile();
            }
            params.getDefaultSerializer().serialize(block, fop);
            fop.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    // [Signature] [PubKey]
    // Pubkey can be uncompressed or compressed .
    // The pubkey is checked by hash.
    //
    public static boolean isInputP2PKH(TransactionInput input) {
        int c = 0;
        boolean result = true;
        if (input.getScriptSig().getChunks().size() != 2)
            return false;

        for (ScriptChunk chunk : input.getScriptSig().getChunks()) {
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            if (c == 0) {
                if (!isSignature(chunk.data))
                    return false;

            } else if (c == 1) {
                // if ((chunk.data.length<60) || (chunk.data.length>80))
                //    return false;
                // pubkey
                if (!ECKey.isPubKeyCanonical(chunk.data))
                    return false;

            }
            c++;


        }

        return result;
    }
    // 03f11163e9c764d248d20e2b5e0be7e969844583c8a0cabd63e31459242b047846 OP_CHECKSIG
    // scriptSig is ONLY the signature

    public static boolean isInputP2PK(TransactionInput input) {
        int c = 0;
        boolean result = true;
        if (input.getScriptSig().getChunks().size() != 1)
            return false;

        for (ScriptChunk chunk : input.getScriptSig().getChunks()) {
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            if (!isSignature(chunk.data))
                return false;


        }

        return result;
    }

    // P2PKXX has a public key hash (~20 bytes), and a signature (~64 bytes)
    public static boolean isInputP2PKXX(TransactionInput input) {
        int c = 0;
        boolean result = true;
        if (input.getScriptSig().getChunks().size() != 2)
            return false;

        for (ScriptChunk chunk : input.getScriptSig().getChunks()) {
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            if (c == 0) {
                if (!isSignature(chunk.data))
                    return false;
            } else if (c == 1) {
                if (ECKey.isPubKeyCanonical(chunk.data))
                    return false; // highly probably it is NOT a hash
                // pubkey
                if ((chunk.data.length < 16) || (chunk.data.length > 20))
                    return false;
            }
            c++;


        }

        return result;
    }

    // Possibilities
    // <sig> {[pubkey] OP_CHECKSIG}


    public static boolean isInputP2SH_PK(TransactionInput input) {
        int c = 0;
        boolean result = true;
        if (input.getScriptSig().getChunks().size() != 2)
            return false;

        for (ScriptChunk chunk : input.getScriptSig().getChunks()) {
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            if (c == 0) {
                if (!isSignature(chunk.data))
                    return false;
            } else if (c == 1) {
                // script
                Script subScript;
                try {
                    subScript = new Script(chunk.data);
                } catch (ScriptException e) {
                    // If script has errors, count as invalid
                    return false;
                }
                if (!subScript.isSentToRawPubKey())
                    return false;
            }
            c++;
        }

        return result;
    }


    static public byte[] getProgram(ScriptChunk chunk) {
        try {
            // Don't round-trip as Bitcoin Core doesn't and it would introduce a mismatch.
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            chunk.write(bos);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    static boolean isPush(int opcode) {
        return (opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16);
    }

    static int decodeFromOpN(int opcode) {
        checkArgument((opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16), "decodeFromOpN called on non OP_N opcode");
        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    static public class KeyStats {
        int count;
        int acNumKeys;
        int acNumSigs;
        int count2of3;
        int count2of2;
        int acSigSize;
    }

    static public boolean isSentToMultiSig(Script script,KeyStats ks) {
        List<ScriptChunk> chunks = script.getChunks();
        if (chunks.size() < 4) return false;
        ScriptChunk chunk = chunks.get(chunks.size() - 1);
        // Must end in OP_CHECKMULTISIG[VERIFY].
        if (!chunk.isOpCode()) return false;
        if (!(chunk.equalsOpCode(OP_CHECKMULTISIG) || chunk.equalsOpCode(OP_CHECKMULTISIGVERIFY))) return false;
        int numKeys = 0;
        int numSigs =0;
        try {
            // Second to last chunk must be an OP_N opcode and there should be that many data chunks (keys).
            ScriptChunk m = chunks.get(chunks.size() - 2);
            if (!m.isOpCode()) return false;
            if (!isPush(m.opcode)) return false;
            numKeys = decodeFromOpN(m.opcode);
            if (numKeys < 1 || chunks.size() != 3 + numKeys) return false;
            for (int i = 1; i < chunks.size() - 2; i++) {
                if (chunks.get(i).isOpCode()) return false;
            }

            int op = chunks.get(0).opcode;
            // First chunk must be an OP_N opcode too.
            if (!isPush(op)) return false;
            numSigs =decodeFromOpN(op);
            if ( numSigs< 1) return false;

            ks.count++;
            ks.acNumKeys +=numKeys;
            ks.acNumSigs +=numSigs;
            ks.acSigSize +=script.getProgram().length;
            if ((numKeys==3) && (numSigs==2)) ks.count2of3++;
            if ((numKeys==2) && (numSigs==2)) ks.count2of2++;

        } catch (IllegalStateException e) {
            return false;   // Not an OP_N opcode.
        }
        return true;
    }

    // OP_FALSE <sig> {2 [pubkey1] [pubkey2] [pubkey3] 3 OP_CHECKMULTISIG}
    public static boolean isInputP2SH_MULTISIG(TransactionInput input,KeyStats ks) {
        int c = 0;
        boolean result = true;
        if (input.getScriptSig().getChunks().size() < 2)
            return false;

        List<ScriptChunk> chunks = input.getScriptSig().getChunks();
        // script
        ScriptChunk lastChunk = chunks.get(chunks.size() - 1);

        if (!lastChunk.isPushData())
            return false;
        Script subScript;
        try {
            subScript = new Script(lastChunk.data);
        } catch (ScriptException e) {
            // If script has errors, count as invalid
            return false;
        }
        if (!isSentToMultiSig(subScript,ks))
            return false;

        for (int i = 0; i < chunks.size() - 1; i++) {
            ScriptChunk chunk = chunks.get(i);
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            if (c == 0) {
                if (!IsDummyPush(chunk))
                    return false;

            } else
            {
                if (!isSignature(chunk.data))
                    return false;
            }
            c++;
        }

        return result;
    }

    static boolean IsDummyPush(ScriptChunk chunk) {

        // This could be anything, but most wallets puts
        // OP_FALSE because it's the smallest. Also OP_1..OP_16 are

        if (chunk.data.length != 0)
            return false;

        if ((chunk.opcode >= (byte) ScriptOpCodes.OP_1) && (chunk.opcode<= (byte) ScriptOpCodes.OP_16))
            return true; // valid, but not used

        if (chunk.opcode != (byte) ScriptOpCodes.OP_FALSE)
            return false;

        return true;
    }

    // OP_FALSE <sig> <sig>
    public static boolean isInputMULTISIG(TransactionInput input) {
        int c =0;
        boolean result =true;
        if (input.getScriptSig().getChunks().size()<2)
            return false;

        List<ScriptChunk>  chunks  =input.getScriptSig().getChunks();

        for (int i=0;i<chunks.size();i++) {
            ScriptChunk chunk = chunks.get(i);
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            if (c==0) {
                if (!IsDummyPush(chunk))
                    return false;
            } else
            {
                if (!isSignature(chunk.data))
                    return false;
            }
            c++;
        }

        return result;
    }


    static boolean IsValidSignatureEncoding(byte[] sig) {
        // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
        // * total-length: 1-byte length descriptor of everything that follows,
        //   excluding the sighash byte.
        // * R-length: 1-byte length descriptor of the R value that follows.
        // * R: arbitrary-length big-endian encoded R value. It must use the shortest
        //   possible encoding for a positive integers (which means no null bytes at
        //   the start, except a single one when the next byte has its highest bit set).
        // * S-length: 1-byte length descriptor of the S value that follows.
        // * S: arbitrary-length big-endian encoded S value. The same rules apply.
        // * sighash: 1-byte value indicating what data is hashed (not part of the DER
        //   signature)

        // Minimum and maximum size constraints.
        if (sig.length < 9) return false;
        if (sig.length > 73) return false;

        // A signature is of type 0x30 (compound).
        if (sig[0] != 0x30) return false;

        // Make sure the length covers the entire signature.
        if (sig[1] != sig.length - 3) return false;

        // Extract the length of the R element.
        int lenR = sig[3];

        // Make sure the length of the S element is still inside the signature.
        if (5 + lenR >= sig.length) return false;

        // Extract the length of the S element.
        int lenS = sig[5 + lenR];

        // Verify that the length of the signature matches the sum of the length
        // of the elements.
        if (((lenR + lenS + 7) != sig.length)) return false;

        // Check whether the R element is an integer.
        if (sig[2] != 0x02) return false;

        // Zero-length integers are not allowed for R.
        if (lenR == 0) return false;

        // Negative numbers are not allowed for R.
        if ((sig[4] & 0x80)!=0) return false;

        // Null bytes at the start of R are not allowed, unless R would
        // otherwise be interpreted as a negative number.
        if (lenR > 1 && (sig[4] == 0x00) && ((sig[5] & 0x80)==0)) return false;

        // Check whether the S element is an integer.
        if (sig[lenR + 4] != 0x02) return false;

        // Zero-length integers are not allowed for S.
        if (lenS == 0) return false;

        // Negative numbers are not allowed for S.
        if ((sig[lenR + 6] & 0x80)!=0) return false;

        // Null bytes at the start of S are not allowed, unless S would otherwise be
        // interpreted as a negative number.
        if (lenS > 1 && (sig[lenR + 6] == 0x00) && (sig[lenR + 7] & 0x80)==0) return false;

        return true;
    }

    static boolean isSignature(byte[] data ) {

            return IsValidSignatureEncoding(data);
        /*
            ECKey.ECDSASignature signature;
            try {
                signature = ECKey.ECDSASignature.decodeFromDER(data);
            } catch (RuntimeException x) {
                // Doesn't look like a signature.
                return false;
            }
            return true;
*/
    }

    // Este testeo no es muy preciso
    public static boolean isInputP2SH(TransactionInput input) {
        int c =0;
        boolean result =true;
        if (input.getScriptSig().getChunks().size()<2)
            return false;

        List<ScriptChunk>  chunks  =input.getScriptSig().getChunks();
        // script
        ScriptChunk lastChunk = chunks.get(chunks.size()-1);

        if (!lastChunk.isPushData())
            return false;

        // If it looks like a signature, almost sure it is not a script
        if (isSignature(lastChunk.data))
            return false;

        // IF is looks like a public key, surely it is not a script
        if (ECKey.isPubKeyCanonical(lastChunk.data))
            return false;


        Script subScript;
        try {
            subScript =  new Script(lastChunk.data);
        } catch (ScriptException e) {
            // If script has errors, count as invalid
            return false;
        }
        for (int i=0;i<chunks.size()-1;i++) {
            ScriptChunk chunk = chunks.get(i);
            if (chunk.data == null)
                return false;
            if (!chunk.isPushData())
                return false;

            c++;
        }

        return result;
    }

    public static void breakme()
    {
        return;
    }

    public static void main(String[] args) throws BlockStoreException, VerificationException, PrunedException {

        NetworkParameters params = MainNetParams.get();
        Context context = new Context(params);

        BlockAnalysis ba = new BlockAnalysis();
        //String fileName = "C:\\Users\\Sergio\\Downloads\\00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.bin";
        String fileName = "0.bin";
        int acInputs = 0;
        int acOutputs = 0;
        int acInputs2 =0; // inputs, for transactions with 2 outputs
        int countOutputs2=0;
        int count1i1o= 0;
        int countNi1o= 0;
        int acOpReturn = 0;
        int acSentToCLTVPaymentChannel = 0;
        int acPayToScriptHash = 0;
        int acSentToMultiSig = 0;
        int acSentToAddress = 0;
        int acSentToRawPubKey = 0;
        int acTransactions = 0;
        int acUnknown = 0;
        int acInvalid =0;
        int acOverlapedTypes =0;
        int acInputP2PKH =0;
        int acInputP2SH_MULTISIG =0;
        int acInputP2SH=0;
        int acInputP2SH_PK =0;
        int acInputP2PK=0;
        int acInputP2PKXX=0;
        int acInputMULTISIG=0;
        int acInputP2SHSize=0;

        int acMainChainSpace =0;
        int acSegwitSpace=0;
        int transactionFixedLength = 10;
        int acTotalSize=0;
        int inputFixedLength = 40;
        int outputFixedLength = 9;


        KeyStats ksi = new KeyStats();
        KeyStats kso = new KeyStats();

        for (int bn=0;bn<1000;bn++) {
            fileName = String.format(Locale.US, "%d.bin", bn);
            System.out.println("Reading block "+fileName);
            Block block = ba.importBlock(params, fileName);
            System.out.println("done");


            List<Transaction> transactions = block.getTransactions();
            acTransactions += transactions.size();
            int blocks = 1;
            for (int i = 0; i < transactions.size(); i++) {
                Transaction t = transactions.get(i);
                List<TransactionInput> inputs = t.getInputs();
                List<TransactionOutput> outputs = t.getOutputs();

                if (outputs.size()==2) {
                    acInputs2 += inputs.size();
                    countOutputs2++;
                }

                if ((inputs.size()==1) && (outputs.size()==1)) {
                    count1i1o++;
                    //System.out.println("Small tx: "+t.getHashAsString());
                } else
                if (outputs.size()==1) {
                    countNi1o++;
                    //System.out.println("Small tx: "+t.getHashAsString());
                }
                acInputs += inputs.size();
                acOutputs += outputs.size();

                acMainChainSpace +=transactionFixedLength;
                acTotalSize      +=t.getMessageSize();

                // Skip coinbase input because it is a mal-formed script
                if (i!=0)
                for (int j = 0; j < inputs.size(); j++) {
                    // identify type of input
                    TransactionInput input = inputs.get(j);
                    int iFound =0;
                    boolean isMULTISIG = isInputMULTISIG(input);

                    acMainChainSpace +=inputFixedLength;
                    int  sbytes = input.getScriptBytes().length;

                    if (isMULTISIG) {
                        iFound++;
                        acInputMULTISIG++;
                        //

                    }
                    boolean isP2PKXX  = isInputP2PKXX(input);
                    if (isP2PKXX) {
                        iFound++;
                        acInputP2PKXX++;

                    }
                    // P2SH multisignatures can only be detected in inputs
                    boolean isP2PKH = isInputP2PKH(input);
                    if (isP2PKH) {
                        iFound++;
                        // Turns witness
                        acSegwitSpace +=sbytes;
                        acInputP2PKH++;

                    }

                    boolean isP2SH_MULTISIG = isInputP2SH_MULTISIG(input,ksi);
                    if (isP2SH_MULTISIG ) {
                        iFound++;
                        acInputP2SH_MULTISIG++;
                    }
                    boolean isP2SH= isInputP2SH(input);
                    if (isP2SH) {
                        iFound++;
                        acInputP2SH++;
                        acSegwitSpace +=sbytes; // Turns into P2WSH
                        acInputP2SHSize +=input.getScriptBytes().length;
                    }
                    if ((!isP2SH) && (!isP2PKH))
                        acMainChainSpace +=sbytes;

                    boolean isP2SH_PK = isInputP2SH_PK(input);
                    if (isP2SH_PK ) {
                        iFound++;
                        acInputP2SH_PK++;
                    }
                    boolean isP2PK = isInputP2PK(input);
                    if (isP2PK ) {
                        iFound++;
                        acInputP2PK++;
                    }
                    if (iFound==0) {
                        breakme();
                        //boolean xisP2SH_PK = xisInputP2SH_PK(input);
                        // Asumo
                        System.out.println("Cannot recognize: "+t.getHashAsString()+" input "+j);
                        System.out.println("Input: "+input.getOutpoint().toString());
                    }

                }

                for (int j = 0; j < outputs.size(); j++) {
                    // identify type of input
                    TransactionOutput output = outputs.get(j);
                    boolean isInvalid =false;

                    acMainChainSpace +=outputFixedLength;

                    // Here he must make some adjustments, depending on the output type
                    int outScriptSize  = output.getScriptBytes().length;

                    Script script = null;
                    try {
                    script = output.getScriptPubKey();
                    } catch (ScriptException e) {
                        // If script has errors, count as invalid
                        isInvalid=true;
                    }
                    boolean isOpReturn = false;
                    boolean isSentToCLTVPaymentChannel = false;
                    boolean isPayToScriptHash = false;
                    boolean isSentToMultiSig = false;
                    boolean isSentToAddress = false;
                    boolean isSentToRawPubKey = false;

                    if (!isInvalid) {
                        isOpReturn = (script.isOpReturn());
                        isSentToCLTVPaymentChannel = (script.isSentToCLTVPaymentChannel());
                        isPayToScriptHash = (script.isPayToScriptHash());
                        //isSentToMultiSig = (script.isSentToMultiSig());
                        isSentToMultiSig = isSentToMultiSig(script,kso); // this is uncommon now, not a single case seen
                        isSentToAddress = (script.isSentToAddress());
                        isSentToRawPubKey = (script.isSentToRawPubKey());
                    }
                    int found = 0;

                    if (isInvalid) {
                        acInvalid++;
                        found++;
                    }

                    if (isOpReturn) {
                        acOpReturn++;
                        found++;
                    }
                    if (isSentToCLTVPaymentChannel) {
                        acSentToCLTVPaymentChannel++;
                        found++;
                    }
                    if (isPayToScriptHash) {
                        acPayToScriptHash++;
                        // This will be turned into P2WSH
                        // Original sig:  OP_HASH160 [20-byte-hash-value] OP_EQUAL (22 bytes total)
                        // New sig: 0 <32-byte-hash> (0x0020{32-byte-hash})
                        acMainChainSpace +=33;
                        found++;
                    }
                    if (isSentToMultiSig) {
                        acSentToMultiSig++;
                        found++;
                    }
                    if (isSentToAddress) {
                        acSentToAddress++;
                        //scriptPubKey: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
                        // new: 0 <20-byte-key-hash> (0x0014{20-byte-key-hash}) (22)
                        acMainChainSpace +=22;
                        found++;
                    }
                    if (isSentToRawPubKey) {
                        acSentToRawPubKey++;
                        found++;
                    }

                    // if it is not isPayToScriptHash or isSentToAddress , assume no modification will be made
                    if ((!isSentToAddress) && (!isPayToScriptHash))
                        acMainChainSpace +=outScriptSize;

                    if (found > 1)
                        acOverlapedTypes++;
                    if (found == 0)
                        acUnknown++;
                }
            }
        }
        // Result
        System.out.println("Result:");
        System.out.println("acTotalSize =" + acTotalSize);
        int segNoSegSize = acMainChainSpace+acSegwitSpace;

        System.out.println("segNoSegSize (seg+noseg) =" + segNoSegSize );
        System.out.println("Ratio SegNoSeg/total=" + 1.0 * acTotalSize / segNoSegSize);


        System.out.println("acMainChainSpace =" + acMainChainSpace);
        System.out.println("acSegwitSpace =" + acSegwitSpace);
        System.out.println("Ratio seg/noseg=" + 1.0 * acSegwitSpace / acMainChainSpace);


        System.out.println("acInputs =" + acInputs);
        System.out.println("acOutputs =" + acOutputs);
        System.out.println("acInputs2 =" + acInputs2);
        System.out.println("countOutputs2 =" + countOutputs2);

        System.out.println("countOutputs2[%] =" + getPercent(countOutputs2,acTransactions)+"%"); //81%

        System.out.println("count1i1o="+count1i1o);
        System.out.println("count1i1o[%]="+getPercent(count1i1o,acTransactions)+"%");

        System.out.println("countNi1o="+countNi1o);
        System.out.println("countNi1o[%]="+getPercent(countNi1o,acTransactions)+"%");

        System.out.println("avg. Inputs2/transaction2 =" + acInputs2*1.0/countOutputs2);
        System.out.println("avg. Inputs/transaction =" + acInputs*1.0/acTransactions);
        System.out.println("avg. Outputs/transaction =" + acOutputs*1.0/acTransactions);

        System.out.println("acTransactions =" + acTransactions);
        System.out.println("Multisigs:");

        System.out.println("ksi.count="+ksi.count);
        System.out.println("ksi.acNumSigs="+ksi.acNumSigs);
        System.out.println("ksi.acNumKeys="+ksi.acNumKeys);
        System.out.println("ksi.count2of2="+ksi.count2of2);
        System.out.println("ksi.count2of3="+ksi.count2of3);
        System.out.println("ksi.acSigSize="+ksi.acSigSize);
/*
        System.out.println("kso.count="+kso.count);
        System.out.println("kso.acNumSigs="+kso.acNumSigs);
        System.out.println("kso.acNumKeys="+kso.acNumKeys);
        System.out.println("kso.count2of2="+kso.count2of2);
        System.out.println("kso.count2of3="+kso.count2of3);
*/

        System.out.println("Inputs:");
        System.out.println("acInputP2SHSize="+acInputP2SHSize);
        System.out.println("acInputP2PKH="+acInputP2PKH);
        System.out.println("acInputP2SH="+acInputP2SH);
        System.out.println("acInputP2SH_MULTISIG="+acInputP2SH_MULTISIG);
        System.out.println("acInputP2SH_PK="+acInputP2SH_PK);
        System.out.println("acInputP2PK="+acInputP2PK);
        System.out.println("acInputMULTISIG="+acInputMULTISIG);
        System.out.println("Outputs:");
        System.out.println("acOpReturn=" + acOpReturn);
        System.out.println("acSentToCLTVPaymentChannel=" + acSentToCLTVPaymentChannel);
        System.out.println("acPayToScriptHash=" + acPayToScriptHash);
        System.out.println("acSentToMultiSig=" + acSentToMultiSig);
        System.out.println("acSentToAddress=" + acSentToAddress);
        System.out.println("acSentToRawPubKey=" + acSentToRawPubKey);
        System.out.println("acUnknown=" + acUnknown);
        System.out.println("acInvalid=" + acInvalid);
        System.out.println("acOverlapedTypes="+acOverlapedTypes);
        int outputSum = acOpReturn + acSentToCLTVPaymentChannel + acPayToScriptHash
                + acPayToScriptHash + acSentToMultiSig + acSentToAddress
                + acSentToRawPubKey + acUnknown;

        System.out.println("outputSum=" + acOutputs);
        System.out.println("Averages------------------------:");
        System.out.println("Multisigs:");
        System.out.println("ksi Avg.NumSigs="+ksi.acNumSigs*1.0/ksi.count);
        System.out.println("ksi Avg.NumKeys="+ksi.acNumKeys*1.0/ksi.count);
        System.out.println("ksi count2of2="+getPercent(ksi.count2of2,ksi.count)+"%");
        System.out.println("ksi count2of3="+getPercent(ksi.count2of3,ksi.count)+"%");
        System.out.println("ksi.Avg SigSize="+ksi.acSigSize*1.0/ksi.count);
/*
        System.out.println("kso Avg.NumSigs="+kso.acNumSigs*1.0/kso.count);
        System.out.println("kso Avg.NumKeys="+kso.acNumKeys*1.0/kso.count);
        System.out.println("kso count2of2="+getPercent(kso.count2of2,kso.count)+"%");
        System.out.println("kso count2of3="+getPercent(kso.count2of3,kso.count)+"%");
*/
        System.out.println("Inputs:");
        System.out.println("Avg.InputP2SHSize="+acInputP2SHSize*1.0/acInputP2SH);
        System.out.println("acInputP2PKH="+getPercent(acInputP2PKH,acInputs)+"%");
        System.out.println("acInputP2SH="+getPercent(acInputP2SH,acInputs)+"%");
        System.out.println("acInputP2SH_MULTISIG="+getPercent(acInputP2SH_MULTISIG,acInputs)+"%");
        System.out.println("acInputP2SH_PK="+getPercent(acInputP2SH_PK,acInputs)+"%");
        System.out.println("acInputP2PK="+getPercent(acInputP2PK,acInputs)+"%");
        System.out.println("acInputMULTISIG="+getPercent(acInputMULTISIG,acInputs)+"%");

        System.out.println("Outputs:");

        System.out.println("avOpReturn=" + getPercent(acOpReturn,acOutputs)+"%");
        System.out.println("avSentToCLTVPaymentChannel=" + getPercent(acSentToCLTVPaymentChannel,acOutputs)+"%");
        System.out.println("avPayToScriptHash=" + getPercent(acPayToScriptHash,acOutputs)+"%");
        System.out.println("avSentToMultiSig=" + getPercent(acSentToMultiSig,acOutputs)+"%");
        System.out.println("avSentToAddress=" + getPercent(acSentToAddress,acOutputs)+"%");
        System.out.println("avSentToRawPubKey=" + getPercent(acSentToRawPubKey,acOutputs)+"%");
        System.out.println("avUnknown=" + getPercent(acUnknown,acOutputs)+"%");
        System.out.println("acInvalid=" + getPercent(acInvalid,acOutputs)+"%");
        System.out.println("avOverlapedTypes="+getPercent(acOverlapedTypes,acOutputs)+"%");

    }

    static double getPercent(int n,int t) {
        return n*100.0/t;
    }
}

