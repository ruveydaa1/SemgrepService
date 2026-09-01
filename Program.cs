using SemgrepService.Application.Interfaces;
using SemgrepService.Infrastructure.Semgrep;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenApi();
builder.Services.AddControllers();

// Semgrep service
builder.Services.AddSingleton<ISemgrepService, SemgrepScanService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Internal API Key protection
app.Use(async (context, next) =>
{
    // Sadece Semgrep scan endpoint'ini koru
    if (context.Request.Path.StartsWithSegments("/api/semgrep/scan"))
    {
        var configuredApiKey =
            app.Configuration["InternalApiKey"];

        var requestApiKey =
            context.Request.Headers["X-Internal-Api-Key"]
                .FirstOrDefault();

        if (string.IsNullOrWhiteSpace(configuredApiKey) ||
            requestApiKey != configuredApiKey)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;

            await context.Response.WriteAsync(
                "Unauthorized: Invalid or missing API key.");

            return;
        }
    }

    await next();
});

app.MapControllers();

app.Run();