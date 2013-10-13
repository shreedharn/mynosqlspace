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
 * This class populates the mongo db with documents containing set of passwords read from a text file and its equivalent
 * SHA512 hash
 * @author : Shreedhar Natarajan
 * Date: 9/29/13
 */
public class MongoHashDocGenerator implements Runnable {
    final static int THREAD_POOL_SIZE = 5;
    final static int OBJECTS_PER_INSERT = 20000;
    final static Logger logger = Logger.getLogger(MongoHashDocGenerator.class.getName());
    private static final String FIELD_TXT = "txt";
    private static final String FIELD_SHA512 = "SHA512";
    private static final String MONGO_DB_NAME = "Password";
    private static final String MONGO_COLLECTION_NAME = "PasswordDocs";
    final ThreadPoolExecutor executorService;
    final LinkedBlockingQueue<String> passwordEntries = new LinkedBlockingQueue<String>();
    final DB database;
    final DBCollection collection;


    public MongoHashDocGenerator() throws UnknownHostException {
        executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(MongoHashDocGenerator.THREAD_POOL_SIZE);
        MongoClient client = new MongoClient();
        database = client.getDB(MONGO_DB_NAME);
        collection = database.getCollection(MONGO_COLLECTION_NAME);
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
            password = passwordEntries.poll();
            for (int i = 0; password != null; i++) {
                byte[] bytesOfMessage = hashCalc.getUtF8BytesOfText(password);
                // A simple place holder object
                PasswordDocument passwordDocument = new PasswordDocument();
                passwordDocument.passwd = password;
                //32-bytes digest size
                passwordDocument.sha512dig = hashCalc.getDigestString(bytesOfMessage, HashCalculator.HASH_SHA512);
                DBObject dbObject = null;
                dbObject = new BasicDBObject()
                        .append(FIELD_TXT, passwordDocument.passwd)
                        .append(FIELD_SHA512, passwordDocument.sha512dig);
                dbObjectList.add(dbObject);

                // when variable i reaches OBJECTS_PER_INSERT. do a mongo insert
                if (i == OBJECTS_PER_INSERT) {  // => Simply use comparison instead of Mod operation
                    inserIntoMongodb(dbObjectList);
                    dbObjectList.clear();
                    i = 0; // reset i;
                }
                password = passwordEntries.poll();
            }
            if (dbObjectList.size() > 0) {
                inserIntoMongodb(dbObjectList);
                dbObjectList.clear();
            }
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
        }
    }

    public synchronized void inserIntoMongodb(final List<DBObject> dbObjectList) {
        collection.insert(dbObjectList.toArray(new DBObject[0]));
    }

    public void readTextFile(String fileName) throws IOException {
        FileReader fr = null;
        BufferedReader br = null;
        long startMillis = 0;
        long endMillis = 0;


        try {
            fr = new FileReader(fileName);
            br = new BufferedReader(fr);
            String line;
            System.out.println("Press any key to continue ...");
            System.in.read();
            System.out.println("Reading the file ...");
            startMillis = System.currentTimeMillis();
            for (line = br.readLine(); line != null; line = br.readLine()) {
                passwordEntries.add(line);
            }
            endMillis = System.currentTimeMillis();
            System.out.println("File read in " + (endMillis - startMillis) + " ms");
            System.out.println("Press any key to continue ...");
            System.in.read();
            System.out.println("Processing ...");

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

            mongoHashDocGenerator.readTextFile(args[0]);
            System.out.println("Total # of password to process " + mongoHashDocGenerator.passwordEntries.size());
            startMillis = System.currentTimeMillis();
            while (!mongoHashDocGenerator.passwordEntries.isEmpty()) {
                if (mongoHashDocGenerator.executorService.getActiveCount() < MongoHashDocGenerator.THREAD_POOL_SIZE)
                    mongoHashDocGenerator.executorService.execute(mongoHashDocGenerator);
                else {
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
        String sha512dig;

        public String toString() {
            return "** Original String: " + passwd + "\n" +
                    "SHA512: " + sha512dig;
        }
    }
}
