package com.example.drive.folder;

import com.example.drive.user.User;
import com.example.drive.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/folders")
@RequiredArgsConstructor
public class FolderController {

    private final FolderRepository folderRepository;
    private final UserRepository userRepository;
    private final FolderService folderService;

    // ---------------- Create Folder ----------------
    @PostMapping
    public FolderDto createFolder(@RequestParam String name,
                                  @RequestParam(required = false) Long parentId,
                                  Principal principal) {
        User user = userRepository.findByEmail(principal.getName()).orElseThrow();
        Folder parent = parentId == null ? null :
                folderRepository.findByIdAndOwner(parentId, user).orElseThrow();

        if (folderRepository.existsByNameAndParentAndOwner(name, parent, user)) {
            throw new RuntimeException("Folder already exists in this location");
        }

        Folder folder = Folder.builder()
                .name(name)
                .parent(parent)
                .owner(user)
                .build();

        folderRepository.save(folder);

        return new FolderDto(folder.getId(), folder.getName(),
                folder.getParent() != null ? folder.getParent().getId() : null);
    }

    // ---------------- List Subfolders ----------------
    @GetMapping("/{id}/items")
    public List<FolderDto> listFolders(@PathVariable Long id, Principal principal) {
        User user = userRepository.findByEmail(principal.getName()).orElseThrow();
        Folder parent = id == 0 ? null :
                folderRepository.findByIdAndOwner(id, user).orElseThrow();

        return folderRepository.findByParentAndOwner(parent, user)
                .stream()
                .map(f -> new FolderDto(f.getId(), f.getName(),
                        f.getParent() != null ? f.getParent().getId() : null))
                .toList();
    }

    // ---------------- Delete Folder ----------------
    @DeleteMapping("/{id}")
    public String deleteFolder(@PathVariable Long id, Principal principal) {
        User user = userRepository.findByEmail(principal.getName()).orElseThrow();
        Folder folder = folderRepository.findByIdAndOwner(id, user).orElseThrow();

        folderRepository.delete(folder); // later you can add recursive delete if files exist
        return "Folder deleted successfully";
    }

    // ---------------- Rename Folder ----------------
    @PutMapping("/{id}/rename")
    public FolderDto renameFolder(@PathVariable Long id,
                                  @RequestParam String newName,
                                  Principal principal) {
        User user = userRepository.findByEmail(principal.getName()).orElseThrow();
        Folder folder = folderRepository.findByIdAndOwner(id, user).orElseThrow();

        if (folderRepository.existsByNameAndParentAndOwner(newName, folder.getParent(), user)) {
            throw new RuntimeException("A folder with this name already exists in the same location");
        }

        folder.setName(newName);
        folderRepository.save(folder);

        return new FolderDto(folder.getId(), folder.getName(),
                folder.getParent() != null ? folder.getParent().getId() : null);
    }
}
