import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class Zipper {
    private static String password;
    private static CountDownLatch latch;
    private static Path sourceRootPath;

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Zipper <folder-path>");
            return;
        }

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password: ");
        password = scanner.nextLine();
        scanner.close();
        
        sourceRootPath = Paths.get(args[0]);
        Path outputDir = Paths.get(args[0] + "_processed");
        
        if (!Files.exists(outputDir)) {
            try {
                Files.createDirectories(outputDir);
            } catch (IOException e) {
                System.err.println("Failed to create output directory: " + e.getMessage());
                return;
            }
        }
        
        final List<Path> filesToProcess = new ArrayList<>();
        try {
            Files.walkFileTree(sourceRootPath, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    filesToProcess.add(file);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            System.err.println("Error walking directory: " + e.getMessage());
            return;
        }

        latch = new CountDownLatch(filesToProcess.size());
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        
        for (Path file : filesToProcess) {
            processFile(file, outputDir, executor);
        }
        
        try {
            latch.await(10, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            System.err.println("Processing interrupted: " + e.getMessage());
        } finally {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
            }
        }
        
        System.out.println("File processing completed.");
    }

    private static void processFile(Path file, Path outputDir, ExecutorService executor) {
        executor.submit(() -> {
            try {
                String fileName = file.toString().toLowerCase();
                if (fileName.endsWith(".zip") || fileName.endsWith(".enc")) {
                    decryptAndUnzip(file, outputDir);
                } else {
                    byte[] data = Files.readAllBytes(file);
                    encrypt(data, file, outputDir);
                }
            } catch (IOException e) {
                System.err.println("Error processing file: " + file + ": " + e.getMessage());
            } finally {
                latch.countDown();
            }
        });
    }

    private static void encrypt(byte[] data, Path file, Path outputDir) {
        try {
            Path relativePath = sourceRootPath.relativize(file);
            
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            
            byte[] encryptedData = cipher.doFinal(data);
            fileZip(encryptedData, salt, iv, file, outputDir, relativePath);
        } catch (Exception e) {
            System.err.println("Encryption failed for " + file + ": " + e.getMessage());
        }
    }

    private static void fileZip(byte[] encryptedData, byte[] salt, byte[] iv, Path file, Path outputDir, Path relativePath) {
        try {
            Path zipPath = outputDir.resolve(relativePath.getParent() != null 
                ? relativePath.getParent().toString() + ".zip" 
                : "root.zip");
            
            Files.createDirectories(zipPath.getParent());
            
            try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(zipPath.toFile(), true)))) {
                ZipEntry entry = new ZipEntry(relativePath.toString() + ".enc");
                zos.putNextEntry(entry);
                
                zos.write(salt);
                zos.write(iv);
                zos.write(encryptedData);
                
                zos.closeEntry();
            }
        } catch (IOException e) {
            System.err.println("Zipping failed for " + file + ": " + e.getMessage());
        }
    }

    private static void decryptAndUnzip(Path zipFile, Path outputDir) {
        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(zipFile.toFile())))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    zis.closeEntry();
                    continue;
                }

                String entryName = entry.getName();
                if (!entryName.endsWith(".enc")) {
                    System.err.println("Skipping non-encrypted file: " + entryName);
                    zis.closeEntry();
                    continue;
                }

                Path targetFile = outputDir.resolve(entryName.replace(".enc", ""));

                Files.createDirectories(targetFile.getParent());

                byte[] salt = new byte[16];
                byte[] iv = new byte[16];
                
                int saltRead = zis.read(salt);
                int ivRead = zis.read(iv);
                if (saltRead != 16 || ivRead != 16) {
                    System.err.println("Incomplete encryption metadata for " + entryName);
                    zis.closeEntry();
                    continue;
                }

                ByteArrayOutputStream dataBuffer = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = zis.read(buffer)) != -1) {
                    dataBuffer.write(buffer, 0, bytesRead);
                }
                byte[] encryptedData = dataBuffer.toByteArray();
                
                try {
                    byte[] decryptedData = decrypt(encryptedData, salt, iv);
                    
                    Files.write(targetFile, decryptedData);
                    
                    if (targetFile.toString().toLowerCase().endsWith(".zip")) {
                        decryptAndUnzip(targetFile, outputDir);
                    }
                } catch (Exception e) {
                    System.err.println("Failed to decrypt " + entryName + ": " + e.getMessage());
                }

                zis.closeEntry();
            }
        } catch (IOException e) {
            System.err.println("Decryption and unzipping failed for " + zipFile + ": " + e.getMessage());
        }
    }

    private static byte[] decrypt(byte[] encryptedData, byte[] salt, byte[] iv) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        
        return cipher.doFinal(encryptedData);
    }
}