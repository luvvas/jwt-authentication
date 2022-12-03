using Microsoft.EntityFrameworkCore;

using jwtAuthentication.Models;

namespace jwtAuthentication.Data
{
	public class DataContext : DbContext
	{
		public DataContext(DbContextOptions<DataContext> options) : base(options) { }

		public DbSet<User> Users { get; set; }
	}
}
