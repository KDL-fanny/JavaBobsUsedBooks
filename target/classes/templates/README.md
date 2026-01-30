# Thymeleaf Templates

This directory contains Thymeleaf templates for the Bob's Used Books application.

## Template Structure

The templates should be organized as follows:

```
templates/
├── fragments/         # Reusable template fragments (header, footer, etc.)
├── layouts/           # Layout templates
├── books/             # Book-related templates
├── cart/              # Shopping cart templates
├── offers/            # Book resale offer templates
├── orders/            # Order management templates
├── customers/         # Customer management templates
├── admin/             # Admin portal templates
└── error/             # Error pages
```

## Migration Notes

These templates are migrated from the original ASP.NET Core Razor views. When implementing the templates:

1. Convert Razor syntax (@model, @using, etc.) to Thymeleaf syntax (th:text, th:each, etc.)
2. Update form handling to use Spring MVC conventions
3. Update URL paths to match the Spring Boot controller mappings
4. Replace ASP.NET Core Tag Helpers with Thymeleaf equivalents
5. Update authentication/authorization checks to use Spring Security
