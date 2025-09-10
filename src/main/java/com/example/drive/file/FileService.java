package com.example.drive.file;

import com.example.drive.folder.Folder;
import com.example.drive.folder.FolderRepository;
import com.example.drive.user.User;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FileService {

    private static final Logger logger = LoggerFactory.getLogger(FileService.class);

    private final FileObjectRepository fileRepo;
    private final FolderRepository folderRepo;

    @Value("${app.storage.root:./drive-data}")
    private String storageRoot;

    private Path getRootPath() {
        return Paths.get(storageRoot);
    }

    @Transactional
    public FileObject upload(MultipartFile file, Long parentId, User owner) throws IOException {
        logger.info("Starting file upload - File: {}, ParentId: {}, Owner: {}",
                file.getOriginalFilename(), parentId, owner.getEmail());

        // Validate file
        if (file.isEmpty()) {
            throw new RuntimeException("Cannot upload empty file");
        }

        if (!StringUtils.hasText(file.getOriginalFilename())) {
            throw new RuntimeException("File name is required");
        }

        // Validate file size (additional check beyond spring.servlet.multipart.max-file-size)
        if (file.getSize() > 50 * 1024 * 1024) { // 50MB
            throw new RuntimeException("File size exceeds maximum allowed size of 50MB");
        }

        // Ensure storage directory exists
        Path root = getRootPath();
        if (!Files.exists(root)) {
            Files.createDirectories(root);
        }

        // Validate and get parent folder if specified
        Folder parent = null;
        if (parentId != null && parentId != 0) {
            logger.info("Looking for parent folder with ID: {} owned by: {}", parentId, owner.getEmail());
            parent = folderRepo.findByIdAndOwner(parentId, owner)
                    .orElseThrow(() -> {
                        logger.error("Parent folder not found - ID: {}, Owner: {}", parentId, owner.getEmail());
                        return new RuntimeException("Parent folder not found or access denied");
                    });
            logger.info("Found parent folder: {} (ID: {})", parent.getName(), parent.getId());
        } else {
            logger.info("Uploading to root folder (parentId is null or 0)");
        }

        // Generate unique stored filename
        String originalFilename = file.getOriginalFilename();
        String fileExtension = "";
        if (originalFilename.contains(".")) {
            fileExtension = originalFilename.substring(originalFilename.lastIndexOf("."));
        }

        String storedName = UUID.randomUUID().toString() + fileExtension;
        Path destPath = root.resolve(storedName);

        // Ensure we don't overwrite existing files
        while (Files.exists(destPath)) {
            storedName = UUID.randomUUID().toString() + fileExtension;
            destPath = root.resolve(storedName);
        }

        try {
            // Copy file to storage
            Files.copy(file.getInputStream(), destPath, StandardCopyOption.REPLACE_EXISTING);

            // Calculate checksum for integrity verification
            String checksum = calculateChecksum(destPath);

            // Create file object
            FileObject fo = FileObject.builder()
                    .originalName(originalFilename)
                    .storedName(storedName)
                    .contentType(file.getContentType())
                    .sizeBytes(file.getSize())
                    .checksumSha256(checksum)
                    .parent(parent)
                    .owner(owner)
                    .build();

            FileObject saved = fileRepo.save(fo);

            logger.info("File uploaded successfully: {} (ID: {}) in folder: {} by user: {}",
                    originalFilename, saved.getId(),
                    parent != null ? parent.getName() + " (ID: " + parent.getId() + ")" : "root",
                    owner.getEmail());

            return saved;

        } catch (IOException e) {
            // Clean up file if database save fails
            try {
                Files.deleteIfExists(destPath);
            } catch (IOException cleanupEx) {
                logger.warn("Failed to clean up file after error: {}", cleanupEx.getMessage());
            }
            throw new RuntimeException("Failed to store file: " + e.getMessage(), e);
        }
    }

    public List<FileObject> listByFolder(Long parentId, User owner) {
        logger.info("Listing files - ParentId: {}, Owner: {}", parentId, owner.getEmail());

        Folder parent = null;
        if (parentId != null && parentId != 0) {
            parent = folderRepo.findByIdAndOwner(parentId, owner)
                    .orElseThrow(() -> {
                        logger.error("Folder not found - ID: {}, Owner: {}", parentId, owner.getEmail());
                        return new RuntimeException("Folder not found or access denied");
                    });
            logger.info("Found folder: {} (ID: {})", parent.getName(), parent.getId());
        } else {
            logger.info("Listing files in root folder");
        }

        List<FileObject> files = fileRepo.findByParentAndOwner(parent, owner);
        logger.info("Found {} files in folder {}", files.size(), parentId != null ? parentId : "root");

        return files;
    }

    public Path getPath(FileObject fo) {
        Path filePath = getRootPath().resolve(fo.getStoredName());
        if (!Files.exists(filePath)) {
            throw new RuntimeException("File not found in storage: " + fo.getOriginalName());
        }
        return filePath;
    }

    public FileObject requireOwnedFile(Long id, User owner) {
        return fileRepo.findByIdAndOwner(id, owner)
                .orElseThrow(() -> new RuntimeException("File not found or access denied"));
    }

    @Transactional
    public void delete(Long id, User owner) throws IOException {
        FileObject fo = requireOwnedFile(id, owner);
        Path filePath = getRootPath().resolve(fo.getStoredName());

        try {
            Files.deleteIfExists(filePath);
            fileRepo.delete(fo);
            logger.info("File deleted successfully: {} by user: {}", fo.getOriginalName(), owner.getEmail());
        } catch (IOException e) {
            logger.error("Failed to delete file from storage: {}", e.getMessage());
            throw new RuntimeException("Failed to delete file", e);
        }
    }

    @Transactional
    public FileObject rename(Long id, String newName, User owner) {
        if (!StringUtils.hasText(newName)) {
            throw new RuntimeException("New name cannot be empty");
        }

        FileObject fo = requireOwnedFile(id, owner);
        String oldName = fo.getOriginalName();
        fo.setOriginalName(newName.trim());

        FileObject saved = fileRepo.save(fo);
        logger.info("File renamed from '{}' to '{}' by user: {}", oldName, newName, owner.getEmail());
        return saved;
    }

    private String calculateChecksum(Path filePath) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileBytes = Files.readAllBytes(filePath);
            byte[] hashBytes = digest.digest(fileBytes);

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            logger.warn("Failed to calculate checksum: {}", e.getMessage());
            return null;
        }
    }
}