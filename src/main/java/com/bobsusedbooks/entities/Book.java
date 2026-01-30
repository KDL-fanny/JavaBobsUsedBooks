package com.bobsusedbooks.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "books")
@Getter
@Setter
@NoArgsConstructor
public class Book {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String author;
    private String isbn;
    private String description;
    private BigDecimal price;
    private Integer quantity;
    private String coverImageUrl;
    private Boolean isFeatured;
    private Boolean isBestseller;
    private Boolean isNewArrival;
    private LocalDate publishDate;

    private LocalDate lastRestockDate;
    @Column(name = "publish_year")
    private Integer year;
    @Column(length = 1000)
    private String summary;

    private LocalDateTime createdOn;
    private LocalDateTime updatedOn;
    private Boolean isAvailable = true;
    private String createdBy;
    
    // Reference data relationships
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "genre_id")
    private Genre genre;
    
    @Column(name = "genre_id", insertable = false, updatable = false)
    private Long genreId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "publisher_id")
    private Publisher publisher;
    
    @Column(name = "publisher_id", insertable = false, updatable = false)
    private Long publisherId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "book_type_id")
    private BookType bookType;
    
    @Column(name = "book_type_id", insertable = false, updatable = false)
    private Long bookTypeId;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "condition_id")
    private Condition condition;
    
    @Column(name = "condition_id", insertable = false, updatable = false)
    private Long conditionId;
    
    @Column(name = "search_text", length = 1000)
    private String searchText;

    // User listing fields
    @Column(name = "seller_id")
    private Long sellerId;
    private Integer listingStatus;
    private Boolean isUserListing;
    private Boolean isUserOffer;
    private Long offerSourceId;
    
    public Book(String name, String author, BigDecimal price) {
        this.name = name;
        this.author = author;
        this.price = price;
        this.quantity = 1;
        this.isFeatured = false;
        this.isBestseller = false;
        this.isNewArrival = true;
        this.isAvailable = true;
        this.createdOn = LocalDateTime.now();
    }
    
    public String getGenre() {
        return this.genre != null ? this.genre.getName() : "Unknown Genre";
    }
    
    public String getName() {
        return this.name;
    }
    
    public Integer getQuantityAvailable() {
        return this.quantity;
    }

    @PrePersist
    @PreUpdate
    private void prepareSearchText() {
        this.searchText = (name != null ? name.toLowerCase() : "") + " " +
                         (author != null ? author.toLowerCase() : "") + " " +
                         (isbn != null ? isbn.toLowerCase() : "");
    }

}
