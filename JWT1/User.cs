namespace Jwt
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } // Email benzersiz olmalı
        public string Password { get; set; }
    }
}