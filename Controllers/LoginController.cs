using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NyousTarde.Contexts;
using NyousTarde.Domains;

namespace NyousTarde.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        // Chamamos nosso contexto do banco Nyous
        NyousContext _context = new NyousContext();

        // Capturar as infos do token do appsetting.json
        // Variável que irá precorrer todos os métodos com as configurações que foram obtidas
        private IConfiguration _config;

        // Método construtor para passar as config
        public LoginController(IConfiguration config)
        {
            _config = config;
        }

        // Método que vai validar o usuário da app
        
        private Usuario AuthenticateUser(Usuario login)
        {
            // Include irá fazer os JOINS na tabela
         
            return _context.Usuario.Include(a => a.IdAcessoNavigation)
                .FirstOrDefault(u => u.Email == login.Email && u.Senha == login.Senha);
        }

        //Método que irá gerar o Token
     
        private string GenerateJSONWebToken(Usuario userInfo)
        {
            //Definimos uma security key da configuration
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            //Cria a credencial com a security key criada usando um algotimo seguro
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Definimos nossas Claims (dados da sessão) para poderem ser capturadas
            // a qualquer momento enquanto o Token for ativo
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.NameId, userInfo.Nome),
                new Claim(JwtRegisteredClaimNames.Email, userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                // Pega a info de acesso por escrito, ex: Padrão ou Administrador
                new Claim(ClaimTypes.Role, userInfo.IdAcessoNavigation.Tipo)
            };

            // Configuramos nosso Token e seu tempo de vida
            var token = new JwtSecurityToken
                (
                    //Issuer = Emitente = Emissor
                    _config["Jwt:Issuer"],
                    _config["Jwt:Issuer"],
                    claims,
                    //Passa a data de expiração
                    expires: DateTime.Now.AddMinutes(120),
                    signingCredentials: credentials
                );

            // Retorna o Token efeitivamente
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Usamos a anotação "AllowAnonymous" para 
        // ignorar a autenticação neste método, já que é ele quem fará isso
        // Deixamos esse método para o acesso do user
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] Usuario login)
        {
            // Definimos inicialmente como não autorizado
            IActionResult response = Unauthorized();

            // Autenticamos o usuário da API
            var user = AuthenticateUser(login);
            if (user != null)
            {
                // Gera o Token com as informações do usuário
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }
    }
}
