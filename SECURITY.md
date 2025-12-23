# Bank API Security Documentation

This document details all security techniques and measures implemented in the Bank API to ensure a compliant, secure, and modern API design.

## Table of Contents

1. [Authentication & Authorization](#authentication--authorization)
2. [Response Integrity & Signing](#response-integrity--signing)
3. [Token Security & Replay Prevention](#token-security--replay-prevention)
4. [Rate Limiting](#rate-limiting)
5. [Data Privacy & Compliance](#data-privacy--compliance)
6. [CORS (Cross-Origin Resource Sharing)](#cors-cross-origin-resource-sharing)
7. [Input Validation](#input-validation)
8. [Error Handling](#error-handling)
9. [HTTPS/TLS Encryption](#httpstls-encryption)
10. [Dependency Management](#dependency-management)
11. [API Security Standards Compliance](#api-security-standards-compliance)
12. [OpenAPI Documentation Security](#openapi-documentation-security)
13. [Spectral Linting & Security Validation](#spectral-linting--security-validation)
14. [Observability & Security Monitoring](#observability--security-monitoring)
15. [Resilience & Secure Downstream Communication](#resilience--secure-downstream-communication)
16. [Health Checks](#health-checks)

---

## Authentication & Authorization

### Overview
The API implements multiple authentication schemes to support different use cases, with role-based authorization for fine-grained access control.

### Implemented Authentication Schemes

1. **JWT Bearer Authentication** - For user/service authentication with OAuth 2.0 and OpenID Connect
2. **API Key Authentication** - For subscription-based access (compatible with Azure API Management)
3. **OpenID Connect** - For enterprise SSO integration with Microsoft Entra ID

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.Auth.cs`

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddApiKeyInHeader($"{ApiKeyDefaults.AuthenticationScheme}-Header", options =>
    {
        options.KeyName = "Ocp-Apim-Subscription-Key";
        options.Realm = "API";
    })
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = GlobalConfiguration.ApiSettings!.TokenValidation;
        options.TokenValidationParameters.SignatureValidator = (token, _) => new JsonWebToken(token);
    });
```

### Authorization Policies

- **bank_god**: Requires authenticated users with "banker" or "ceo" roles
- **bank_subscription**: Requires valid API key authentication

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
   dotnet add package AspNetCore.Authentication.ApiKey
   ```

2. **Configure Authentication in Program.cs**
   ```csharp
   builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
       .AddJwtBearer(options => {
           options.TokenValidationParameters = new TokenValidationParameters {
               ValidateIssuer = true,
               ValidateAudience = true,
               ValidateLifetime = true,
               ValidateIssuerSigningKey = true,
               ValidIssuers = new[] { "your-issuer" },
               ValidAudiences = new[] { "your-audience" }
           };
       });
   ```

3. **Define Authorization Policies**
   ```csharp
   builder.Services.AddAuthorization(options => {
       options.AddPolicy("RequireAdmin", policy => {
           policy.RequireAuthenticatedUser();
           policy.RequireRole("admin");
       });
   });
   ```

4. **Apply to Endpoints**
   ```csharp
   app.MapGet("/secure-endpoint", () => "Secure data")
      .RequireAuthorization("RequireAdmin");
   ```

---

## Response Integrity & Signing

### Overview
All API responses are signed using JSON Web Signature (JWS) with ECDSA (Elliptic Curve Digital Signature Algorithm) to ensure response integrity and authenticity. This complies with RFC 7515.

### Implementation Details

**File:** `BankApi.Core/Defaults/Helper.JwsResponseSigningMiddleware.cs`

The middleware:
- Signs every response body using ECDSA with ES512 algorithm (P-521 curve)
- Adds the signature to the `X-JWS-Signature` response header
- Uses detached payload format for efficiency
- Includes critical headers: `kid` (Key ID), `alg` (Algorithm), `iat` (Issued At)

**File:** `BankApi.Core/Defaults/Helper.Jwk.cs`

The API exposes a JWKS (JSON Web Key Set) endpoint at `/.well-known/jwks.json` for clients to validate signatures, complying with RFC 7517.

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package jose-jwt
   ```

2. **Create JWK Helper**
   ```csharp
   public static class JwkHelper
   {
       public static Jwk CreateSigningKey()
       {
           var ecSigner = ECDsa.Create(ECCurve.NamedCurves.nistP521);
           return new Jwk(ecSigner, false) { KeyId = "your-key-id" };
       }
   }
   ```

3. **Create Response Signing Middleware**
   ```csharp
   public class JwsResponseSigningMiddleware
   {
       private readonly RequestDelegate _next;
       private readonly Jwk _jwk;
       
       public JwsResponseSigningMiddleware(RequestDelegate next, Jwk jwk)
       {
           _next = next;
           _jwk = jwk;
       }
       
       public async Task InvokeAsync(HttpContext context)
       {
           var originalBodyStream = context.Response.Body;
           using var memoryStream = new MemoryStream();
           context.Response.Body = memoryStream;
           
           await _next(context);
           
           memoryStream.Seek(0, SeekOrigin.Begin);
           byte[] responseBytes = memoryStream.ToArray();
           
           var extraHeaders = new Dictionary<string, object>
           {
               { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
               { "kid", _jwk.KeyId }
           };
           
           string jws = JWT.EncodeBytes(responseBytes, _jwk, JwsAlgorithm.ES512, 
                                       extraHeaders, new JwtOptions { DetachPayload = true });
           
           context.Response.Headers["X-JWS-Signature"] = jws;
           
           memoryStream.Seek(0, SeekOrigin.Begin);
           await memoryStream.CopyToAsync(originalBodyStream);
           context.Response.Body = originalBodyStream;
       }
   }
   ```

4. **Register Middleware and JWKS Endpoint**
   ```csharp
   var jwk = JwkHelper.CreateSigningKey();
   app.UseMiddleware<JwsResponseSigningMiddleware>(jwk);
   
   app.MapGet("/.well-known/jwks.json", () => {
       var keySet = new JwkSet(jwk);
       return Results.Ok(keySet.ToDictionary());
   }).AllowAnonymous();
   ```

5. **Client-Side Validation**
   - Fetch JWKS from `/.well-known/jwks.json`
   - Extract `X-JWS-Signature` header from response
   - Verify signature using the JWK and response body

---

## Token Security & Replay Prevention

### Overview
The API implements token replay detection and prevention specifically for Microsoft Entra ID tokens, blocking subsequent use of the same token and permanently blocking compromised identities.

### Implementation Details

**File:** `BankApi.Core/Defaults/Helper.EntraIdTokenReuseMiddleware.cs`

The middleware:
- Detects token reuse using the `aio` claim (unique per token issuance)
- Blocks all requests from an identity (`oid` claim) if token replay is detected
- Uses HybridCache for distributed token tracking
- Maintains blocks for 10 years to prevent future compromise

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package Microsoft.Extensions.Caching.Hybrid
   ```

2. **Create Token Reuse Middleware**
   ```csharp
   public class EntraIdTokenReuseMiddleware
   {
       private readonly RequestDelegate _next;
       
       public EntraIdTokenReuseMiddleware(RequestDelegate next)
       {
           _next = next;
       }
       
       public async Task InvokeAsync(HttpContext context, HybridCache hybridCache)
       {
           if (context.User.Identity?.IsAuthenticated != true)
           {
               await _next(context);
               return;
           }
           
           var aioClaimValue = context.User.FindFirst("aio")?.Value;
           var oidClaimValue = context.User.FindFirst("oid")?.Value;
           
           if (aioClaimValue == null || oidClaimValue == null)
           {
               await _next(context);
               return;
           }
           
           var oidBlockKey = $"blocked_oid:{oidClaimValue}";
           
           // Check if identity is blocked
           if (await hybridCache.GetOrCreateAsync(oidBlockKey, 
               async _ => false, cancellationToken: context.RequestAborted))
           {
               context.Response.StatusCode = StatusCodes.Status403Forbidden;
               await context.Response.WriteAsync("Forbidden: Identity blocked due to token replay");
               return;
           }
           
           var tokenExpClaimValue = context.User.FindFirst("exp")?.Value!;
           var tokenExpirationTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(tokenExpClaimValue));
           var tokenTimeUntilExpiration = tokenExpirationTime - DateTimeOffset.UtcNow;
           
           var uniqueId = Guid.NewGuid();
           
           // Atomically check and store token
           var tokenReuseResult = await hybridCache.GetOrCreateAsync(
               $"aio:{aioClaimValue}",
               async _ => uniqueId,
               new() { Expiration = tokenTimeUntilExpiration + TimeSpan.FromMinutes(5) },
               cancellationToken: context.RequestAborted
           );
           
           // If not our unique ID, it's a replay
           if (tokenReuseResult != uniqueId)
           {
               await hybridCache.SetAsync(oidBlockKey, true,
                   new() { Expiration = TimeSpan.FromDays(3650) },
                   cancellationToken: context.RequestAborted);
               
               context.Response.StatusCode = StatusCodes.Status403Forbidden;
               await context.Response.WriteAsync("Forbidden: Token replay detected");
               return;
           }
           
           await _next(context);
       }
   }
   ```

3. **Register Services and Middleware**
   ```csharp
   builder.Services.AddHybridCache();
   // Configure distributed cache for production
   builder.Services.AddStackExchangeRedisCache(options => {
       options.Configuration = "your-redis-connection";
   });
   
   app.UseAuthentication();
   app.UseAuthorization();
   app.UseMiddleware<EntraIdTokenReuseMiddleware>();
   ```

---

## Rate Limiting

### Overview
Fixed window rate limiting protects the API from abuse and ensures fair usage across all clients, with per-user or per-host partitioning.

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.RateLimit.cs`

Configuration:
- **Limit:** 40 requests per window
- **Window:** 2 minutes
- **Queue:** 2 requests
- **Partitioning:** By user ID (authenticated) or Host header (anonymous)
- **Response:** 429 Too Many Requests with `Retry-After` header

### How to Implement in Your Project

1. **Add Rate Limiting Services**
   ```csharp
   builder.Services.AddRateLimiter(options =>
   {
       options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
       
       options.AddPolicy("fixed", httpContext =>
       {
           var partitionKey = httpContext.User.Identity?.IsAuthenticated == true
               ? httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
               : httpContext.Request.Headers.Host.ToString();
           
           return RateLimitPartition.GetFixedWindowLimiter(
               partitionKey: partitionKey,
               factory: _ => new FixedWindowRateLimiterOptions
               {
                   AutoReplenishment = true,
                   PermitLimit = 40,
                   QueueLimit = 2,
                   Window = TimeSpan.FromMinutes(2),
                   QueueProcessingOrder = QueueProcessingOrder.OldestFirst
               }
           );
       });
       
       options.OnRejected = async (context, cancellationToken) =>
       {
           if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
           {
               context.HttpContext.Response.Headers.RetryAfter = 
                   ((int)retryAfter.TotalSeconds).ToString();
           }
           await context.HttpContext.Response.WriteAsync(
               "Rate limit exceeded. Please try again later.", cancellationToken);
       };
   });
   ```

2. **Apply Rate Limiting**
   ```csharp
   app.UseRateLimiter();
   
   // Apply to specific endpoints
   app.MapGet("/api/endpoint", () => "Response")
      .RequireRateLimiting("fixed");
   ```

3. **Configure Headers**
   ```csharp
   // Add rate limit info to response headers
   httpContext.Response.Headers["X-Rate-Limit-Limit"] = "40";
   httpContext.Response.Headers["X-Rate-Limit-Remaining"] = 
       remainingRequests.ToString();
   ```

---

## Data Privacy & Compliance

### Overview
The API implements data classification and redaction to comply with GDPR and CCPA, automatically erasing sensitive data from logs.

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.Compliance.cs`, `Helper.Taxonomy.cs`, `Attribute.DataClassification.cs`

Three-tier data classification:
- **UnrestrictedData:** Public data (logged as-is)
- **RestrictedData:** Internal data (redacted/erased in logs)
- **ConfidentialData:** Sensitive data (redacted/erased in logs)

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package Microsoft.Extensions.Compliance.Redaction
   dotnet add package Microsoft.Extensions.Compliance.Classification
   ```

2. **Define Data Classification Taxonomy**
   ```csharp
   public static class DataTaxonomy
   {
       public static string TaxonomyName => typeof(DataTaxonomy).FullName!;
       public static DataClassification PublicData => new(TaxonomyName, "PublicData");
       public static DataClassification SensitiveData => new(TaxonomyName, "SensitiveData");
       public static DataClassification ConfidentialData => new(TaxonomyName, "ConfidentialData");
   }
   ```

3. **Create Classification Attributes**
   ```csharp
   public class PublicDataAttribute : DataClassificationAttribute
   {
       public PublicDataAttribute() : base(DataTaxonomy.PublicData) { }
   }
   
   public class SensitiveDataAttribute : DataClassificationAttribute
   {
       public SensitiveDataAttribute() : base(DataTaxonomy.SensitiveData) { }
   }
   
   public class ConfidentialDataAttribute : DataClassificationAttribute
   {
       public ConfidentialDataAttribute() : base(DataTaxonomy.ConfidentialData) { }
   }
   ```

4. **Configure Redaction**
   ```csharp
   builder.Logging.EnableRedaction();
   
   builder.Services.AddRedaction(redactionBuilder =>
   {
       // Erase sensitive and confidential data
       redactionBuilder.SetRedactor<ErasingRedactor>(
           new DataClassificationSet([
               DataTaxonomy.SensitiveData, 
               DataTaxonomy.ConfidentialData
           ]));
       
       // Don't redact public data
       redactionBuilder.SetRedactor<NullRedactor>(
           new DataClassificationSet(DataTaxonomy.PublicData));
   });
   ```

5. **Use in Models**
   ```csharp
   public class User
   {
       [PublicData]
       public string Username { get; set; }
       
       [SensitiveData]
       public string Email { get; set; }
       
       [ConfidentialData]
       public string SocialSecurityNumber { get; set; }
   }
   ```

6. **Use in Logging**
   ```csharp
   [LoggerMessage(Level = LogLevel.Information, Message = "User accessed data")]
   public static partial void LogUserAccess(ILogger logger, [LogProperties] User user);
   ```

---

## CORS (Cross-Origin Resource Sharing)

### Overview
CORS is configured to allow cross-origin requests from any origin, supporting browser-based API clients.

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.Cors.cs`

Configuration:
- Allows all origins (`*`)
- Allows all headers
- Allows all methods
- Exposes specific headers: `Access-Control-Allow-Origin`, `X-Rate-Limit-Limit`, `Content-Type`

### How to Implement in Your Project

1. **Configure CORS Policy**
   ```csharp
   builder.Services.AddCors(options =>
   {
       options.AddPolicy("ApiCorsPolicy", policy =>
       {
           policy.WithOrigins("https://yourdomain.com")  // Or use AllowAnyOrigin()
                 .AllowAnyHeader()
                 .AllowAnyMethod()
                 .WithExposedHeaders("X-Custom-Header", "X-Rate-Limit-Limit");
       });
   });
   ```

2. **Enable CORS**
   ```csharp
   app.UseCors("ApiCorsPolicy");
   ```

3. **Apply to Specific Endpoints (Optional)**
   ```csharp
   app.MapGet("/api/endpoint", () => "Response")
      .RequireCors("ApiCorsPolicy");
   ```

**Security Note:** In production, restrict origins to known domains instead of allowing all origins.

---

## Input Validation

### Overview
The API uses ASP.NET Core's built-in validation framework to automatically validate request payloads, query parameters, and route parameters.

### Implementation Details

**File:** `BankApi.Service.Stable/Program.cs`

```csharp
builder.Services.AddValidation();
```

The validation framework:
- Validates data annotations on models
- Returns 400 Bad Request for invalid inputs
- Provides detailed validation error messages
- Works with minimal APIs

### How to Implement in Your Project

1. **Enable Validation**
   ```csharp
   builder.Services.AddValidation();
   ```

2. **Define Validated Models**
   ```csharp
   using System.ComponentModel.DataAnnotations;
   
   public class CreateUserRequest
   {
       [Required]
       [StringLength(100, MinimumLength = 3)]
       public string Username { get; set; }
       
       [Required]
       [EmailAddress]
       public string Email { get; set; }
       
       [Range(18, 120)]
       public int Age { get; set; }
       
       [RegularExpression(@"^\d{3}-\d{3}-\d{4}$")]
       public string PhoneNumber { get; set; }
   }
   ```

3. **Use in Endpoints**
   ```csharp
   app.MapPost("/users", (CreateUserRequest request) => 
   {
       // Validation happens automatically
       // If invalid, returns 400 with error details
       return Results.Ok("User created");
   });
   ```

4. **Custom Validation**
   ```csharp
   public class CustomValidationAttribute : ValidationAttribute
   {
       protected override ValidationResult? IsValid(object? value, 
           ValidationContext validationContext)
       {
           // Custom validation logic
           if (/* validation fails */)
           {
               return new ValidationResult("Custom error message");
           }
           return ValidationResult.Success;
       }
   }
   ```

---

## Error Handling

### Overview
Centralized exception handling ensures consistent error responses and prevents information leakage through error messages.

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.ErrorHandling.cs`

Features:
- Global exception handler
- Consistent Problem Details (RFC 7807) responses
- Status code mapping based on exception type
- Request tracing via `requestId`

Exception mapping:
- `InvalidOperationException`, `ArgumentException` → 422 Unprocessable Entity
- `BadHttpRequestException`, `FormatException` → 400 Bad Request
- All others → 500 Internal Server Error

### How to Implement in Your Project

1. **Create Exception Handler**
   ```csharp
   public class GlobalExceptionHandler(IProblemDetailsService problemDetailsService) 
       : IExceptionHandler
   {
       public async ValueTask<bool> TryHandleAsync(
           HttpContext httpContext, 
           Exception exception, 
           CancellationToken cancellationToken)
       {
           var statusCode = exception switch
           {
               InvalidOperationException or ArgumentException => 
                   StatusCodes.Status422UnprocessableEntity,
               BadHttpRequestException or FormatException => 
                   StatusCodes.Status400BadRequest,
               UnauthorizedAccessException => 
                   StatusCodes.Status403Forbidden,
               KeyNotFoundException => 
                   StatusCodes.Status404NotFound,
               _ => StatusCodes.Status500InternalServerError
           };
           
           httpContext.Response.StatusCode = statusCode;
           
           return await problemDetailsService.TryWriteAsync(new()
           {
               Exception = exception,
               HttpContext = httpContext,
               ProblemDetails = new()
               {
                   Status = statusCode,
                   Title = "An error occurred",
                   Detail = exception.Message,
                   Instance = $"{httpContext.Request.Method} {httpContext.Request.Path}"
               }
           });
       }
   }
   ```

2. **Configure Problem Details**
   ```csharp
   builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
   builder.Services.AddProblemDetails(options =>
   {
       options.CustomizeProblemDetails = context =>
       {
           context.ProblemDetails.Extensions.TryAdd(
               "requestId", context.HttpContext.TraceIdentifier);
           context.ProblemDetails.Extensions.TryAdd(
               "timestamp", DateTimeOffset.UtcNow);
       };
   });
   ```

3. **Enable Exception Handler Middleware**
   ```csharp
   app.UseExceptionHandler();
   ```

---

## HTTPS/TLS Encryption

### Overview
The API enforces HTTPS for all communications, with development certificates for local testing and production-grade TLS for deployments.

### Implementation Details

**Files:** `.certs/AspNetDev.pfx`, Launch Settings

Configuration:
- HTTPS development certificates stored in `.certs/`
- HTTPS enabled by default in all launch profiles
- TLS 1.2+ required for production

### How to Implement in Your Project

1. **Generate Development Certificate**
   ```bash
   dotnet dev-certs https --clean
   dotnet dev-certs https -ep ./.certs/aspnetdev.pfx -p 'YourPassword' --trust
   ```

2. **Configure in appsettings.json**
   ```json
   {
     "Kestrel": {
       "Endpoints": {
         "Https": {
           "Url": "https://localhost:5001",
           "Certificate": {
             "Path": ".certs/aspnetdev.pfx",
             "Password": "YourPassword"
           }
         }
       }
     }
   }
   ```

3. **Enforce HTTPS in Production**
   ```csharp
   if (!app.Environment.IsDevelopment())
   {
       app.UseHttpsRedirection();
       app.UseHsts(); // HTTP Strict Transport Security
   }
   ```

4. **Configure HSTS**
   ```csharp
   builder.Services.AddHsts(options =>
   {
       options.Preload = true;
       options.IncludeSubDomains = true;
       options.MaxAge = TimeSpan.FromDays(365);
   });
   ```

---

## Dependency Management

### Overview
Automated dependency updates through Dependabot ensure security vulnerabilities are patched promptly.

### Implementation Details

**File:** `.github/dependabot.yml`

Configuration:
- Weekly automated updates (Thursdays)
- Monitors NuGet packages
- Monitors Dev Container dependencies
- Groups .NET packages together for easier review

### How to Implement in Your Project

1. **Create Dependabot Configuration**
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "nuget"
       directory: "/"
       schedule:
         interval: "weekly"
         day: "thursday"
       groups:
         dotnet:
           patterns:
             - "*"
       open-pull-requests-limit: 10
   ```

2. **Configure Security Updates**
   - Enable Dependabot security updates in repository settings
   - Enable automated security fixes
   - Configure GitHub Advanced Security (if available)

3. **Review and Merge**
   - Review Dependabot PRs regularly
   - Run automated tests before merging
   - Check for breaking changes in release notes

---

## API Security Standards Compliance

### Overview
The API complies with multiple industry standards and best practices for API security and design.

### Compliance Standards

1. **OWASP API Security Top 10 (2023)**
   - Validated via Spectral OWASP ruleset
   - Addresses: Broken Object Level Authorization, Broken Authentication, Broken Object Property Level Authorization, Unrestricted Resource Consumption, Broken Function Level Authorization, Unrestricted Access to Sensitive Business Flows, Server Side Request Forgery, Security Misconfiguration, Improper Inventory Management, Unsafe Consumption of APIs

2. **OpenAPI Specification v3.1.1**
   - Validated via Spectral "oas" ruleset
   - Ensures OpenAPI document validity
   - Enables tooling interoperability

3. **Dutch Public Sector (NLGov) REST API Design Rules**
   - Government-grade API design standards
   - RESTful best practices
   - Naming conventions and structure

4. **RFC 7515 - JSON Web Signature (JWS)**
   - Response signing for integrity
   - Non-repudiation of API responses

5. **RFC 7517 - JSON Web Key Set (JWKS)**
   - Standard key distribution
   - Signature validation support

6. **GDPR and CCPA Compliance**
   - Data classification and redaction
   - Right to be forgotten support
   - Audit logging with data classification

### How to Implement in Your Project

1. **Install Spectral**
   ```bash
   npm install -g @stoplight/spectral-cli
   ```

2. **Create Spectral Configuration**
   ```yaml
   # .spectral.yml
   extends:
     - "spectral:oas"
     - "https://unpkg.com/@stoplight/spectral-owasp-ruleset/dist/ruleset.mjs"
   
   rules:
     # Add custom rules here
     operation-success-response:
       description: Operations must have a success response
       given: $.paths.*[get,post,put,delete,patch]
       severity: warn
       then:
         field: responses
         function: schema
         functionOptions:
           schema:
             type: object
             required: ["200", "201", "204"]
   ```

3. **Run Spectral Validation**
   ```bash
   spectral lint openapi.json
   ```

4. **Integrate into CI/CD**
   ```yaml
   # .github/workflows/api-validation.yml
   name: API Validation
   on: [push, pull_request]
   jobs:
     validate:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: Validate OpenAPI
           uses: stoplightio/spectral-action@latest
           with:
             file_glob: 'Specs.Generated/*.json'
   ```

---

## OpenAPI Documentation Security

### Overview
The API automatically generates OpenAPI documentation with proper security scheme definitions, enabling clients to understand authentication requirements.

### Implementation Details

**Files:** `Builder.OpenApi.cs`, `Transformer.SecurityScheme.cs`

Features:
- Automatic security scheme generation from registered authentication handlers
- Support for Bearer tokens, API keys, and OpenID Connect
- Interactive documentation via Scalar
- Security requirements applied to all operations

Security schemes defined:
- **Bearer Token:** HTTP Bearer authentication with JWT
- **OpenID Connect:** Enterprise SSO integration
- **API Key:** Header-based subscription keys (`Ocp-Apim-Subscription-Key`)

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package Microsoft.AspNetCore.OpenApi
   dotnet add package Scalar.AspNetCore
   ```

2. **Configure OpenAPI Services**
   ```csharp
   builder.Services.AddOpenApi("v1", options =>
   {
       options.AddDocumentTransformer<SecuritySchemeTransformer>();
   });
   ```

3. **Create Security Scheme Transformer**
   ```csharp
   public class SecuritySchemeTransformer(IAuthenticationSchemeProvider authProvider) 
       : IOpenApiDocumentTransformer
   {
       public async Task TransformAsync(OpenApiDocument document, 
           OpenApiDocumentTransformerContext context, 
           CancellationToken cancellationToken)
       {
           var schemes = await authProvider.GetAllSchemesAsync();
           
           document.Components ??= new();
           document.Components.SecuritySchemes ??= new();
           
           foreach (var scheme in schemes)
           {
               if (scheme.Name == JwtBearerDefaults.AuthenticationScheme)
               {
                   document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
                   {
                       Type = SecuritySchemeType.Http,
                       Scheme = "bearer",
                       BearerFormat = "JWT",
                       Description = "JWT Authorization header using the Bearer scheme."
                   };
                   
                   document.Security ??= new();
                   document.Security.Add(new OpenApiSecurityRequirement
                   {
                       {
                           new OpenApiSecuritySchemeReference("Bearer", document),
                           Array.Empty<string>()
                       }
                   });
               }
           }
       }
   }
   ```

4. **Add Scalar UI**
   ```csharp
   app.MapOpenApi();
   
   if (app.Environment.IsDevelopment())
   {
       app.MapScalarApiReference(options =>
       {
           options.Title = "API Documentation";
           options.Theme = ScalarTheme.DeepSpace;
       });
   }
   ```

5. **Customize Security in appsettings.json**
   ```json
   {
     "ApiDocument": {
       "Info": {
         "Title": "Your API",
         "Version": "v1",
         "Description": "API with comprehensive security"
       }
     }
   }
   ```

---

## Spectral Linting & Security Validation

### Overview
Spectral is used to enforce API design rules, security best practices, and compliance standards through automated linting of OpenAPI documents.

### Implementation Details

**Files:** `Specs.Ruleset/main.yml`, `Specs.Ruleset/ruleset.bank.yml`

The project uses multiple Spectral rulesets:
1. **OWASP API Security ruleset** - Validates against OWASP API Security Top 10
2. **OpenAPI Specification ruleset** - Ensures OpenAPI spec compliance
3. **Dutch NLGov ruleset** - Government API design standards
4. **Custom Bank API ruleset** - Project-specific conventions

### Custom Rules Implemented

**Naming Conventions:**
- HTTP headers in Hyphenated-Pascal-Case
- Properties and parameters in camelCase
- Operation IDs in PascalCase

**Documentation Quality:**
- Operation summaries required (max 25 characters)
- Descriptions required (min 15 characters, proper sentences)
- Parameter descriptions required
- Examples required for object types

**Industry Standards:**
- Tags must be from bank industry taxonomy
- Metadata objects must follow specific structure
- Well-formed response metadata

### How Spectral Works in This Project

1. **OpenAPI documents are generated during build** from the ASP.NET Core application
2. **Spectral VSCode extension** automatically validates the generated documents
3. **Problems are highlighted** directly in the OpenAPI JSON files
4. **Rulesets are extensible** allowing for custom project-specific rules

### How to Implement in Your Project

1. **Install Spectral CLI**
   ```bash
   npm install -g @stoplight/spectral-cli
   ```

2. **Install Spectral VSCode Extension**
   - Install "Spectral" extension by Stoplight in VSCode
   - Automatic validation as you edit OpenAPI files

3. **Create Base Ruleset Configuration**
   ```yaml
   # .spectral/main.yml
   extends:
     - spectral:oas  # OpenAPI Specification rules
     - https://unpkg.com/@stoplight/spectral-owasp-ruleset/dist/ruleset.mjs  # OWASP rules
   
   rules:
     # Override or customize rules
     info-contact: error  # Make contact info required
     operation-description: warn
   ```

4. **Create Custom Ruleset**
   ```yaml
   # .spectral/custom-rules.yml
   rules:
     require-api-version:
       description: API version must be specified
       given: $.info.version
       severity: error
       then:
         function: pattern
         functionOptions:
           match: "^v[0-9]+$"
     
     require-security-schemes:
       description: Security schemes must be defined
       given: $.components.securitySchemes
       severity: error
       then:
         function: truthy
     
     require-rate-limit-headers:
       description: Rate limit responses should include rate limit headers
       given: $.paths.*.*.responses.429.headers
       severity: warn
       then:
         field: "Retry-After"
         function: truthy
     
     no-plain-text-passwords:
       description: Password fields should not be in plain text
       given: $..properties[?(@property.match(/password/i))]
       severity: error
       then:
         field: format
         function: enumeration
         functionOptions:
           values: ["password"]
   ```

5. **Create Custom Functions (Advanced)**
   ```javascript
   // .spectral/functions/well-formed-object.js
   module.exports = (targetVal, options, context) => {
     const { elementName, requiredProperties, optionalProperties } = options;
     
     if (!targetVal || !targetVal[elementName]) {
       return [];
     }
     
     const obj = targetVal[elementName];
     const objProps = Object.keys(obj.properties || {});
     
     // Check required properties exist
     const missingRequired = requiredProperties.filter(
       prop => !objProps.includes(prop)
     );
     
     if (missingRequired.length > 0) {
       return [{
         message: `${elementName} is missing required properties: ${missingRequired.join(', ')}`
       }];
     }
     
     // Check for unexpected properties
     const allowedProps = [...requiredProperties, ...optionalProperties];
     const unexpectedProps = objProps.filter(prop => !allowedProps.includes(prop));
     
     if (unexpectedProps.length > 0) {
       return [{
         message: `${elementName} has unexpected properties: ${unexpectedProps.join(', ')}`
       }];
     }
     
     return [];
   };
   ```

6. **Reference Custom Functions**
   ```yaml
   # .spectral/custom-rules.yml
   functionsDir: "./functions"
   functions:
     - well-formed-object
   
   rules:
     validate-metadata-structure:
       description: Metadata must have correct structure
       message: "{{error}}"
       severity: warn
       given: $.paths.*.*.responses[*].content[*].schema.properties
       then:
         function: well-formed-object
         functionOptions:
           elementName: "metadata"
           requiredProperties:
             - count
           optionalProperties:
             - page
             - hasMorePages
             - totalCount
             - pageSize
   ```

7. **Extend Multiple Rulesets**
   ```yaml
   # .spectral/main.yml
   extends:
     - ./custom-rules.yml
     - spectral:oas
     - https://unpkg.com/@stoplight/spectral-owasp-ruleset/dist/ruleset.mjs
   
   rules:
     # Override specific rules if needed
     openapi3: "off"  # Disable if too strict
   ```

8. **Run Spectral Validation**
   ```bash
   # Validate a single file
   spectral lint openapi.json
   
   # Validate with specific ruleset
   spectral lint openapi.json --ruleset .spectral/main.yml
   
   # Output as JSON for CI/CD
   spectral lint openapi.json --format json
   
   # Fail on warnings
   spectral lint openapi.json --fail-severity warn
   ```

9. **Integrate into Build Process**
   ```xml
   <!-- In .csproj file -->
   <Target Name="ValidateOpenApi" AfterTargets="Build">
     <Exec Command="spectral lint $(OutputPath)/openapi.json" />
   </Target>
   ```

10. **Setup CI/CD Integration**
    ```yaml
    # .github/workflows/api-lint.yml
    name: API Linting
    on: [push, pull_request]
    
    jobs:
      lint:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          
          - name: Install Spectral
            run: npm install -g @stoplight/spectral-cli
          
          - name: Lint OpenAPI Document
            run: spectral lint Specs.Generated/*.json --fail-severity warn
    ```

### Benefits of This Approach

- **Automated Security Validation:** OWASP rules catch common API security issues
- **Consistency:** Enforces naming conventions and structure across the API
- **Quality:** Ensures documentation is complete and helpful
- **Compliance:** Validates against industry standards (OpenAPI, NLGov)
- **Extensibility:** Custom rules for project-specific requirements
- **Developer Experience:** Real-time feedback in IDE via VSCode extension
- **CI/CD Integration:** Catches issues before deployment

### Key Spectral Features Used

1. **Rule Composition:** Combining multiple rulesets for comprehensive validation
2. **JSONPath Queries:** Precise targeting of OpenAPI document elements
3. **Custom Functions:** Reusable validation logic for complex scenarios
4. **Severity Levels:** Error/Warn/Info for different validation levels
5. **Custom Messages:** Clear, actionable error messages

---

## Observability & Security Monitoring

### Overview
OpenTelemetry provides comprehensive observability for security monitoring, including traces, metrics, and logs with sensitive data redaction.

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.Logging.cs`

Features:
- Distributed tracing with ASP.NET Core and HttpClient instrumentation
- Metrics collection for performance monitoring
- Entity Framework Core query instrumentation
- OTLP (OpenTelemetry Protocol) export
- Integration with .NET Aspire Dashboard

Security monitoring capabilities:
- Track authentication failures
- Monitor rate limit violations
- Detect token replay attempts
- Audit data access with classification
- Trace request flows for security analysis

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package OpenTelemetry.Extensions.Hosting
   dotnet add package OpenTelemetry.Instrumentation.AspNetCore
   dotnet add package OpenTelemetry.Instrumentation.Http
   dotnet add package OpenTelemetry.Instrumentation.EntityFrameworkCore
   dotnet add package OpenTelemetry.Exporter.OpenTelemetryProtocol
   ```

2. **Configure OpenTelemetry**
   ```csharp
   var otel = builder.Services.AddOpenTelemetry();
   
   otel.WithLogging(logging =>
   {
       // Configure logging
   }, options =>
   {
       options.IncludeFormattedMessage = true;
       options.IncludeScopes = true;
   });
   
   otel.WithMetrics(metrics =>
   {
       metrics.AddAspNetCoreInstrumentation();
       metrics.AddHttpClientInstrumentation();
       metrics.AddRuntimeInstrumentation();
   });
   
   otel.WithTracing(tracing =>
   {
       tracing.AddAspNetCoreInstrumentation(options =>
       {
           // Enrich traces with security context
           options.EnrichWithHttpRequest = (activity, httpRequest) =>
           {
               activity.SetTag("http.user.id", 
                   httpRequest.HttpContext.User.FindFirst("sub")?.Value);
               activity.SetTag("http.authenticated", 
                   httpRequest.HttpContext.User.Identity?.IsAuthenticated);
           };
       });
       tracing.AddHttpClientInstrumentation();
       tracing.AddEntityFrameworkCoreInstrumentation();
   });
   
   otel.UseOtlpExporter();
   ```

3. **Configure OTLP Exporter**
   ```json
   {
     "OpenTelemetry": {
       "Endpoint": "http://localhost:4317",
       "Protocol": "grpc"
     }
   }
   ```

4. **Add Security Logging**
   ```csharp
   public class SecurityEventLogger
   {
       private readonly ILogger<SecurityEventLogger> _logger;
       
       public SecurityEventLogger(ILogger<SecurityEventLogger> logger)
       {
           _logger = logger;
       }
       
       [LoggerMessage(Level = LogLevel.Warning, 
           Message = "Authentication failed for user {UserId}")]
       public partial void LogAuthenticationFailure(string userId);
       
       [LoggerMessage(Level = LogLevel.Warning, 
           Message = "Rate limit exceeded for {PartitionKey}")]
       public partial void LogRateLimitExceeded(string partitionKey);
       
       [LoggerMessage(Level = LogLevel.Critical, 
           Message = "Token replay detected for identity {Oid}")]
       public partial void LogTokenReplay(string oid);
       
       [LoggerMessage(Level = LogLevel.Information, 
           Message = "Access to {ResourceType} by user {UserId}")]
       public partial void LogResourceAccess(string resourceType, string userId);
   }
   ```

5. **Create Security Metrics**
   ```csharp
   public class SecurityMetrics
   {
       private readonly Counter<int> _authFailures;
       private readonly Counter<int> _rateLimitExceeded;
       private readonly Counter<int> _tokenReplays;
       private readonly Histogram<double> _requestDuration;
       
       public SecurityMetrics(IMeterFactory meterFactory)
       {
           var meter = meterFactory.Create("BankApi.Security");
           
           _authFailures = meter.CreateCounter<int>(
               "auth.failures",
               description: "Number of authentication failures");
           
           _rateLimitExceeded = meter.CreateCounter<int>(
               "ratelimit.exceeded",
               description: "Number of rate limit violations");
           
           _tokenReplays = meter.CreateCounter<int>(
               "token.replays",
               description: "Number of token replay attempts");
           
           _requestDuration = meter.CreateHistogram<double>(
               "http.request.duration",
               unit: "ms",
               description: "HTTP request duration");
       }
       
       public void RecordAuthFailure() => _authFailures.Add(1);
       public void RecordRateLimitExceeded() => _rateLimitExceeded.Add(1);
       public void RecordTokenReplay() => _tokenReplays.Add(1);
       public void RecordRequestDuration(double duration) => 
           _requestDuration.Record(duration);
   }
   ```

6. **Use Aspire Dashboard for Development**
   ```bash
   docker run --rm -it \
     -p 18888:18888 \
     -p 4317:18889 \
     --name aspire-dashboard \
     mcr.microsoft.com/dotnet/aspire-dashboard:latest
   ```

---

## Resilience & Secure Downstream Communication

### Overview
The API uses resilience patterns when calling downstream APIs to ensure reliability and security, with service discovery for endpoint resolution.

### Implementation Details

**File:** `BankApi.Core/Defaults/Builder.DownstreamApi.cs`

Features:
- Standard resilience handler (retry, circuit breaker, timeout)
- Service discovery for dynamic endpoint resolution
- Kiota-generated clients for type-safe API calls
- Automatic error handling and recovery

Resilience strategies:
- **Retry:** Automatic retry with exponential backoff
- **Circuit Breaker:** Prevents cascading failures
- **Timeout:** Enforces request time limits
- **Bulkhead:** Isolates resource consumption

### How to Implement in Your Project

1. **Install Required Packages**
   ```bash
   dotnet add package Microsoft.Extensions.Http.Resilience
   dotnet add package Microsoft.Extensions.ServiceDiscovery
   ```

2. **Configure Service Discovery**
   ```csharp
   builder.Services.AddServiceDiscovery();
   
   builder.Services.ConfigureHttpClientDefaults(http =>
   {
       http.AddStandardResilienceHandler();  // Add resilience
       http.AddServiceDiscovery();          // Add service discovery
   });
   ```

3. **Register Downstream API Clients**
   ```csharp
   builder.Services.AddHttpClient<IDownstreamApiClient, DownstreamApiClient>(
       client =>
       {
           client.BaseAddress = new Uri("https://downstream-api");
           client.DefaultRequestHeaders.Add("User-Agent", "BankApi/1.0");
       })
       .AddStandardResilienceHandler(options =>
       {
           options.Retry.MaxRetryAttempts = 3;
           options.Retry.BackoffType = DelayBackoffType.Exponential;
           options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(10);
           options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(30);
       });
   ```

4. **Configure Service Discovery Endpoints**
   ```json
   {
     "Services": {
       "downstream-api": {
         "https": ["https://api.example.com"],
         "http": ["http://localhost:5000"]
       }
     }
   }
   ```

5. **Use Kiota for Type-Safe Clients**
   ```bash
   # Generate client from OpenAPI
   kiota generate --language csharp \
     --openapi https://api.example.com/openapi.json \
     --class-name DownstreamApiClient \
     --namespace-name DownstreamClients
   ```

6. **Custom Resilience Policies**
   ```csharp
   builder.Services.AddHttpClient("custom-resilience")
       .AddResilienceHandler("custom-pipeline", pipelineBuilder =>
       {
           // Retry with custom policy
           pipelineBuilder.AddRetry(new HttpRetryStrategyOptions
           {
               MaxRetryAttempts = 3,
               Delay = TimeSpan.FromSeconds(1),
               BackoffType = DelayBackoffType.Exponential,
               ShouldHandle = args => ValueTask.FromResult(
                   args.Outcome.Result?.StatusCode >= HttpStatusCode.InternalServerError)
           });
           
           // Circuit breaker
           pipelineBuilder.AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions
           {
               FailureRatio = 0.5,
               SamplingDuration = TimeSpan.FromSeconds(10),
               MinimumThroughput = 5,
               BreakDuration = TimeSpan.FromSeconds(30)
           });
           
           // Timeout
           pipelineBuilder.AddTimeout(TimeSpan.FromSeconds(30));
       });
   ```

---

## Health Checks

### Overview
Health check endpoints allow monitoring systems to verify API availability and readiness, with authentication required for access.

### Implementation Details

**File:** `BankApi.Service.Stable/Program.cs`

```csharp
app.MapHealthChecks("/health").RequireAuthorization("bank_subscription");
```

Features:
- Protected by API key authentication
- Returns 200 OK when healthy
- Can be extended with custom health checks
- Supports liveness and readiness probes

### How to Implement in Your Project

1. **Add Basic Health Checks**
   ```csharp
   builder.Services.AddHealthChecks();
   
   app.MapHealthChecks("/health");
   app.MapHealthChecks("/health/ready");  // Readiness probe
   app.MapHealthChecks("/health/live");   // Liveness probe
   ```

2. **Add Database Health Check**
   ```csharp
   builder.Services.AddHealthChecks()
       .AddSqlServer(
           connectionString: builder.Configuration.GetConnectionString("Database"),
           healthQuery: "SELECT 1",
           name: "database",
           failureStatus: HealthStatus.Unhealthy,
           tags: new[] { "db", "sql" }
       );
   ```

3. **Add Custom Health Checks**
   ```csharp
   public class ApiKeyHealthCheck : IHealthCheck
   {
       private readonly IConfiguration _configuration;
       
       public ApiKeyHealthCheck(IConfiguration configuration)
       {
           _configuration = configuration;
       }
       
       public Task<HealthCheckResult> CheckHealthAsync(
           HealthCheckContext context,
           CancellationToken cancellationToken = default)
       {
           var apiKey = _configuration["ApiKey"];
           
           if (string.IsNullOrEmpty(apiKey))
           {
               return Task.FromResult(
                   HealthCheckResult.Unhealthy("API key not configured"));
           }
           
           return Task.FromResult(HealthCheckResult.Healthy("API key configured"));
       }
   }
   
   builder.Services.AddHealthChecks()
       .AddCheck<ApiKeyHealthCheck>("api-key");
   ```

4. **Add Downstream API Health Check**
   ```csharp
   builder.Services.AddHealthChecks()
       .AddUrlGroup(
           new Uri("https://downstream-api/health"),
           name: "downstream-api",
           failureStatus: HealthStatus.Degraded
       );
   ```

5. **Custom Health Check Response**
   ```csharp
   app.MapHealthChecks("/health", new HealthCheckOptions
   {
       ResponseWriter = async (context, report) =>
       {
           context.Response.ContentType = "application/json";
           
           var result = JsonSerializer.Serialize(new
           {
               status = report.Status.ToString(),
               checks = report.Entries.Select(e => new
               {
                   name = e.Key,
                   status = e.Value.Status.ToString(),
                   description = e.Value.Description,
                   duration = e.Value.Duration.TotalMilliseconds
               }),
               totalDuration = report.TotalDuration.TotalMilliseconds
           });
           
           await context.Response.WriteAsync(result);
       }
   });
   ```

6. **Configure Health Check UI**
   ```csharp
   builder.Services.AddHealthChecksUI(options =>
   {
       options.AddHealthCheckEndpoint("API", "/health");
       options.SetEvaluationTimeInSeconds(30);
   }).AddInMemoryStorage();
   
   app.MapHealthChecksUI();
   ```

---

## Summary

The Bank API implements a comprehensive, defense-in-depth security strategy that addresses:

- **Authentication & Authorization:** Multiple authentication schemes with role-based access control
- **Data Integrity:** JWS response signing with ECDSA for non-repudiation
- **Replay Protection:** Advanced token reuse detection and prevention
- **Rate Limiting:** Fair usage enforcement with per-user quotas
- **Data Privacy:** GDPR/CCPA compliant data classification and redaction
- **Input Validation:** Automatic request validation with detailed error messages
- **Error Handling:** Consistent, secure error responses preventing information leakage
- **Transport Security:** HTTPS/TLS encryption for all communications
- **Standards Compliance:** OWASP, OpenAPI, NLGov, RFC standards adherence
- **Automated Validation:** Spectral linting for security and design rule enforcement
- **Observability:** Comprehensive monitoring with OpenTelemetry
- **Resilience:** Robust downstream communication with retry and circuit breaker patterns
- **Dependency Security:** Automated updates via Dependabot

All these techniques work together to create a secure, compliant, and production-ready API that serves as a reference implementation for modern API development.

---

## Getting Started with Security Implementation

To implement these security measures in your own project:

1. **Start with Authentication & Authorization** - This is the foundation
2. **Add Input Validation** - Prevent malicious or malformed requests
3. **Implement Error Handling** - Ensure consistent, secure error responses
4. **Enable HTTPS/TLS** - Encrypt all communications
5. **Add Rate Limiting** - Protect against abuse
6. **Implement Observability** - Monitor for security events
7. **Add Response Signing** - Ensure response integrity (optional but recommended)
8. **Configure Data Privacy** - Classify and redact sensitive data
9. **Setup Spectral Linting** - Automate security and design validation
10. **Enable Dependency Updates** - Keep dependencies patched

Each section above includes detailed implementation steps and code examples to help you apply these techniques to your projects.
