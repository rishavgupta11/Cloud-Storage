package com.example.drive.folder;

import com.example.drive.user.User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class FolderService {

    private final FolderRepository folderRepository;

    public FolderService(FolderRepository folderRepository) {
        this.folderRepository = folderRepository;
    }

    public List<Folder> listFolders(Long parentId, User user) {
        Folder parent = null;
        if (parentId != null) {
            parent = folderRepository.findByIdAndOwner(parentId, user)
                    .orElseThrow(() -> new RuntimeException("Parent folder not found or not owned by user"));
        }
        return folderRepository.findByParentAndOwner(parent, user);
    }

    public Folder createFolder(String name, Long parentId, User user) {
        Folder parent = null;
        if (parentId != null) {
            parent = folderRepository.findByIdAndOwner(parentId, user)
                    .orElseThrow(() -> new RuntimeException("Parent folder not found or not owned by user"));
        }

        if (folderRepository.existsByNameAndParentAndOwner(name, parent, user)) {
            throw new RuntimeException("Folder already exists");
        }

        Folder folder = Folder.builder()
                .name(name)
                .parent(parent)
                .owner(user)
                .build();

        return folderRepository.save(folder);
    }
}

