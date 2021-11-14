using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthWebApi.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        [Route("Login")]
        public IActionResult Login(string username,string password)
        {
            if ((username != "admin") && (password != "password"))
            {
                return BadRequest("Either worng username or password");
            }
            var roles = new List<string> { "Role1", "Role2" };
            var token = GenerateJwtToken(username, roles);

            return Ok(token);
        }

        private string GenerateJwtToken(string username, List<string> roles)
        {
            // Prepare User Claims
            var claims = new List<Claim>
            {
                 new Claim(JwtRegisteredClaimNames.Sub, username),
                 new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                 new Claim(ClaimTypes.NameIdentifier, username)
            };
            roles.ForEach(role =>
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            });

            // Key
            string temp = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("Token")["JwtKey"];
            SymmetricSecurityKey key = null;
            if (temp != null)
            {
                key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(temp));
            }
            //Hashing Algorithm
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            //Token Expire Date
            var expires = DateTime.Now.AddHours(Convert.ToDouble(new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("Token")["JwtExpireDays"]));

            //Create The Token
            var token = new JwtSecurityToken(
                   new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("Token")["JwtIssuer"],
                   new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("Token")["JwtIssuer"],
                   claims,
                   expires: expires,
                   signingCredentials: creds
           );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
