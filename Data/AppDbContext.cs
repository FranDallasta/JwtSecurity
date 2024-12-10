using Microsoft.EntityFrameworkCore;
using JwtSecurity.Models;

namespace JwtSecurity.Data // Ensure this matches your project's namespace and folder structure
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        // Either make Users nullable or initialize it with null suppression (!)
        public DbSet<User> Users { get; set; } = null!;
    }
}
