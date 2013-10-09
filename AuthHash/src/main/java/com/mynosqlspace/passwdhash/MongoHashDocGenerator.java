package com.mynosqlspace.passwdhash;

import com.mongodb.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class populates the mongo db with documents of word hashes for a set of passwords read from a text file
 * @author : Shreedhar Natarajan
 * Date: 9/29/13
 */
public class MongoHashDocGenerator implements Runnable {
    final static int THREAD_POOL_SIZE = 5;
    final static int OBJECTS_PER_INSERT = 20000;
    private static final String FIELD_TXT = "txt";
    private static final String FIELD_MD5 = "MD5";
    private static final String FIELD_SHA1 = "SHA1";
    private static final String FIELD_SHA256 = "SHA256";


    final ThreadPoolExecutor executorService;
    final static Logger logger = Logger.getLogger(MongoHashDocGenerator.class.getName());
    final LinkedBlockingQueue<String> passwordEntryQueue = new LinkedBlockingQueue<String>();
    final DB database;
    final DBCollection collection;


    public MongoHashDocGenerator() throws UnknownHostException{
        executorService =  (ThreadPoolExecutor)Executors.newFixedThreadPool(MongoHashDocGenerator.THREAD_POOL_SIZE);
        MongoClient client = new MongoClient();
        database = client.getDB("Password");
        collection= database.getCollection("PasswordDocs");
        logger.setLevel(Level.INFO);

    }
    void shutdownAndAwaitTermination(ExecutorService pool) {
        pool.shutdown(); // Disable new tasks from being submitted
        try {
            // Wait a while for existing tasks to terminate
            // 2 Minutes is a sufficiently large time for the set that is used
            if (!pool.awaitTermination(2, TimeUnit.MINUTES)) {
                pool.shutdownNow(); // Cancel currently executing tasks
                // Wait a while for tasks to respond to being cancelled
                if (!pool.awaitTermination(60, TimeUnit.SECONDS))
                    logger.severe("Pool did not terminate");
            }
        } catch (InterruptedException ie) {
            // (Re-)Cancel if current thread also interrupted
            pool.shutdownNow();
            // Preserve interrupt status
            Thread.currentThread().interrupt();
        }
    }
    public void run() {
        String password = null;
        final List<DBObject> dbObjectList = new ArrayList<DBObject>(OBJECTS_PER_INSERT);
        final HashCalculator hashCalc = new HashCalculator();
        try {
            password = passwordEntryQueue.poll();
            for (int i = 0; password != null; i++) {
                byte[] bytesOfMessage = hashCalc.getUtF8BytesOfText(password);
                // A simple place holder object
                PasswordDocument passwordDocument = new PasswordDocument();
                passwordDocument.passwd = password;
                passwordDocument.md5dig = hashCalc.getDigestString(bytesOfMessage, HashCalculator.HASH_MD5);
                passwordDocument.sha1dig = hashCalc.getDigestString(bytesOfMessage, HashCalculator.HASH_SHA1);
                passwordDocument.sha256dig = hashCalc.getDigestString(bytesOfMessage, HashCalculator.HASH_SHA256);
                DBObject dbObject = null;
                dbObject = new BasicDBObject()
                        .append(FIELD_TXT,passwordDocument.passwd)
                        .append(FIELD_MD5,passwordDocument.md5dig)
                        .append(FIELD_SHA1,passwordDocument.sha1dig)
                        .append(FIELD_SHA256,passwordDocument.sha256dig);
                dbObjectList.add(dbObject);

                // when variable i reaches OBJECTS_PER_INSERT. do a mongo insert
                if (i == OBJECTS_PER_INSERT) {  // => Simply use comparison instead of Mod operation
                    inserIntoMongodb(dbObjectList);
                    dbObjectList.clear();
                    i = 0; // reset i;
                }
                password = passwordEntryQueue.poll();
            }
            if (dbObjectList.size() > 0 ) {
                inserIntoMongodb(dbObjectList);
                dbObjectList.clear();
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }
    public synchronized void inserIntoMongodb(final List<DBObject> dbObjectList){
        collection.insert(dbObjectList.toArray(new DBObject[0]));
    }
    public void readTextFileName(String fileName) throws IOException {
        FileReader fr = null;
        BufferedReader br = null;
        long startMillis = 0;
        long endMillis = 0;

        try {
            fr = new FileReader(fileName);
            br = new BufferedReader(fr);
            String string;
            startMillis = System.currentTimeMillis();
            for (string = br.readLine(); string != null; string = br.readLine()) {
                passwordEntryQueue.offer(string);
            }
            endMillis = System.currentTimeMillis();
            logger.info("File read in " + (endMillis - startMillis));
        } finally {
            if (br != null)
                br.close();
            if (fr != null)
                fr.close();
        }


    }
    public static void main(String[] args) {
        try {
            MongoHashDocGenerator mongoHashDocGenerator = new MongoHashDocGenerator();
            long startMillis = 0;
            long endMillis = 0;
            if (args.length < 1) {
                logger.severe("Input file containing password list not provided !");
                return;
            }

            mongoHashDocGenerator.readTextFileName(args[0]);
            logger.info("Total # of password to process " + mongoHashDocGenerator.passwordEntryQueue.size());
            startMillis = System.currentTimeMillis();
            while (!mongoHashDocGenerator.passwordEntryQueue.isEmpty()){
                if (mongoHashDocGenerator.executorService.getActiveCount() < MongoHashDocGenerator.THREAD_POOL_SIZE )
                    mongoHashDocGenerator.executorService.execute(mongoHashDocGenerator);
                else  {
                    Thread.sleep(500);
                }
            }
            mongoHashDocGenerator.shutdownAndAwaitTermination(mongoHashDocGenerator.executorService);
            endMillis = System.currentTimeMillis();
            logger.info("Mongo document generated in " + (endMillis - startMillis));

        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }

    }
    final class PasswordDocument {
        String passwd;
        String md5dig;
        String sha1dig;
        String sha256dig;
        public String toString() {
            return "** Original String: "+ passwd + "\n" +
                    "MD5: " + md5dig + "\n"+
                    "SHA1: " + sha1dig + "\n"+
                    "SHA256: " + sha256dig;
        }
    }
}
