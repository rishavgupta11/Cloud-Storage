package com.example.drive.folder;

import com.example.drive.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FolderRepository extends JpaRepository<Folder, Long> {
    List<Folder> findByParentAndOwner(Folder parent, User owner);
    Optional<Folder> findByIdAndOwner(Long id, User owner);
    boolean existsByNameAndParentAndOwner(String name, Folder parent, User owner);
}
