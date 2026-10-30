using Microsoft.AspNetCore.Mvc;
using CyberAgent.DTOs;
using CyberAgent.Services;

namespace CyberAgent.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _auth;
    public AuthController(AuthService auth) => _auth = auth;

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var result = await _auth.RegisterAsync(dto);
        return result == null ? BadRequest("Email already exists.") : Ok(result);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        var result = await _auth.LoginAsync(dto);
        return result == null ? Unauthorized("Invalid credentials.") : Ok(result);
    }
}
