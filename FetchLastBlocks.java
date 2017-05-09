package org.bitcoinj.examples;


import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.H2FullPrunedBlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.Future;

/**
 * Created by Sergio on 12/04/2017.
 */
public class FetchLastBlocks {


    static   Sha256Hash initialHash = Sha256Hash.wrap("0000000000000000020629cb90d370dd08743e3c0ecb7f9836e6594b3e5e2e03");


    static public void exportBlock(NetworkParameters params, Block block,String fileName) {
        FileOutputStream fop = null;
        File file;

        try {
            file = new File(fileName);
            if (file.exists())
                return;

            fop = new FileOutputStream(file);

            // if file doesnt exists, then create it
            if (!file.exists()) {
                file.createNewFile();
            }
            params.getDefaultSerializer().serialize(block,fop);
            fop.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) throws Exception {
        WalletAppKit kit = new WalletAppKit(MainNetParams.get(), new java.io.File("."), "test");
        //Block b =kit.chain().getBlockStore().get(initialHash).getHeader();
        //System.out.println(b);

        kit.startAsync();
        kit.awaitRunning();
        BlockChain chain = kit.chain();
        BlockStore bs = chain.getBlockStore();
        Peer peer = kit.peerGroup().getDownloadPeer();
        PeerGroup peerGroup =kit.peerGroup();
        //Block b = peer.getBlock(bs.getChainHead().getHeader().getHash()).get();
        //System.out.println(b);

        BriefLogFormatter.init();
        System.out.println("Connecting to node");
        final NetworkParameters params = MainNetParams.get();



        //

        Sha256Hash blockHash = initialHash;
        for(int i=0;i<1000;i++) {
            String fn =""+i+".bin";
            File f = new File(fn);
            if(f.exists()) {
                System.out.println("Block exists: "+i);
                continue;
            }
            Future<Block> future = peer.getBlock(blockHash);
            System.out.println("Waiting for node to send us the requested block "+i+": " + blockHash);
            Block block = future.get();
            //System.out.println(block);
            exportBlock(params,block,fn);
            blockHash = block.getPrevBlockHash();
        }

        System.out.println("Stopping..");

        peerGroup.stopAsync();
    }
}
