using Microsoft.AspNetCore.Identity;

namespace jwt_demo.Entities;

public class User : IdentityUser
{
    public string FirstName { get; set; } = default!;
    public string LastName { get; set; } = default!;
}