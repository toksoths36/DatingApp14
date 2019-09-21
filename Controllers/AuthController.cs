using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    private readonly IAuthRepository _repo;
    private readonly IConfiguration _config;
    public AuthController(IAuthRepository repo, IConfiguration config)
    {
      _config = config;
      _repo = repo;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
    {
      userForRegisterDto.Username = userForRegisterDto.Username.ToLower();

      //Κοιταω αν ο χρηστης υπαρχει ηδη
      if (await _repo.UserExists(userForRegisterDto.Username))
      {
        return BadRequest("Username already exists");
      }

      var userToCreate = new User
      {

        Username = userForRegisterDto.Username

      };

      var createdUser = await _repo.Register(userToCreate, userForRegisterDto.Password);

      return StatusCode(201);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
    {
       //Check if the user with this username exists
       var userFromRepo=await _repo.Login(userForLoginDto.Username.ToLower() , userForLoginDto.Password.ToLower());
       
       if (userFromRepo == null)
       {
         return Unauthorized();
       }

       //Create Token

       //Step 1 Claims
       var claims=new []
       {
         new Claim(ClaimTypes.NameIdentifier , userFromRepo.Id.ToString()),
         new Claim(ClaimTypes.Name,userFromRepo.Username)
       };

       //Step 2 Key
       var key=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

       //Step 3 Sign in credentials with key
       var creds=new SigningCredentials(key,SecurityAlgorithms.HmacSha256Signature);

       //Step 4 Token Descriptor(Subject,Expire,Creds)
       var tokenDescriptor=new SecurityTokenDescriptor
       {
         Subject = new ClaimsIdentity(claims),
         Expires = DateTime.Now.AddDays(1),
         SigningCredentials = creds
       };

       //Step 5 TokenHandler
       var tokenHandler = new JwtSecurityTokenHandler();

       //Step 6 Create the Token
       var token=tokenHandler.CreateToken(tokenDescriptor);

       //return token as javascript object
       return Ok( new 
      {
         token = tokenHandler.WriteToken(token) 
      });
    }

  }
}