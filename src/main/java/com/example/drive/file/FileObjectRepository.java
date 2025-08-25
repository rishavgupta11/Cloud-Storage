package com.example.drive.file;

import com.example.drive.folder.Folder;
import com.example.drive.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface FileObjectRepository extends JpaRepository<FileObject, Long> {
    List<FileObject> findByParentAndOwner(Folder parent, com.example.drive.user.User owner);
    java.util.Optional<FileObject> findByIdAndOwner(Long id, com.example.drive.user.User owner);

}

