package com.example.drive.folder;

import com.example.drive.user.User;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "folders",
        uniqueConstraints = @UniqueConstraint(columnNames = {"name", "parent_id", "user_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Folder {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    // Self-reference for parent folder
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private Folder parent;

    // Owner (User) - Fixed column name to match database
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false) // Changed from "owner_id" to "user_id"
    private User owner;

    @CreationTimestamp
    private Instant createdAt;
}