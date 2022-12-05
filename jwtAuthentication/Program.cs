using Microsoft.EntityFrameworkCore;

using jwtAuthentication.Data;
using jwtAuthentication.Services;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAutoMapper(typeof(Program).Assembly);

builder.Services.AddScoped<IAuthService, AuthService>();

builder.Services
	.AddEntityFrameworkNpgsql()
	.AddDbContext<DataContext>(options =>
	{
		options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
	});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
