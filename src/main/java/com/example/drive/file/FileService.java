package com.example.drive.file;

import com.example.drive.folder.Folder;
import com.example.drive.folder.FolderRepository;
import com.example.drive.user.User;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FileService {

    private final FileObjectRepository fileRepo;
    private final FolderRepository folderRepo;

    private final Path root = Paths.get("./drive-data");

    @Transactional
    public FileObject upload(MultipartFile file, Long parentId, User owner) throws IOException {
        // ensure storage dir
        if (!Files.exists(root)) Files.createDirectories(root);

        Folder parent = null;
        if (parentId != null) {
            parent = folderRepo.findByIdAndOwner(parentId, owner)
                    .orElseThrow(() -> new RuntimeException("Folder not found or not yours"));
        }

        String storedName = UUID.randomUUID() + "_" + file.getOriginalFilename();
        Path dest = root.resolve(storedName);
        Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);

        FileObject fo = FileObject.builder()
                .originalName(file.getOriginalFilename())
                .storedName(storedName)
                .contentType(file.getContentType())
                .sizeBytes(file.getSize())
                .parent(parent)
                .owner(owner)
                .build();

        return fileRepo.save(fo);
    }

    public List<FileObject> listByFolder(Long parentId, User owner) {
        Folder parent = null;
        if (parentId != null && parentId != 0) {
            parent = folderRepo.findByIdAndOwner(parentId, owner)
                    .orElseThrow(() -> new RuntimeException("Folder not found or not yours"));
        }
        return fileRepo.findByParentAndOwner(parent, owner);
    }

    public Path getPath(FileObject fo) {
        return root.resolve(fo.getStoredName());
    }

    public FileObject requireOwnedFile(Long id, User owner) {
        return fileRepo.findByIdAndOwner(id, owner)
                .orElseThrow(() -> new RuntimeException("File not found or not yours"));
    }

    @Transactional
    public void delete(Long id, User owner) throws IOException {
        FileObject fo = requireOwnedFile(id, owner);
        Files.deleteIfExists(getPath(fo));
        fileRepo.delete(fo);
    }

    @Transactional
    public FileObject rename(Long id, String newName, User owner) {
        FileObject fo = requireOwnedFile(id, owner);
        fo.setOriginalName(newName);
        return fileRepo.save(fo);
    }
}
