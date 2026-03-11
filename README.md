# Argon2id (Hybrid Hashing)

O problema dos algoritmos de hash tradicionais (como bcrypt) é a dependência exclusiva do custo de CPU, o que os torna vulneráveis ao poder de processamento paralelo das GPUs modernas. O [Argon2](https://password-hashing.net/) resolve essa falha arquitetural introduzindo a restrição de memória (Memory-Hard). Ao exigir alocação pesada de RAM, ele neutraliza a vantagem de hardware do atacante, tornando o custo do ataque computacionalmente inviável.

O algoritmo possui três variantes: Argon2i (otimizado contra ataques side-channel), Argon2d (otimizado contra ataques de GPU) e Argon2id, a versão híbrida recomendada para o hash de senhas.


A eficácia do algoritmo depende da configuração correta dos parâmetros abaixo: 

* **Pepper**: Mesmo não sendo obrigatorio para o funcionamento o pepper é uma chave secreta global concatenada à senha, armazenada isoladamente do banco de dados. Protege os hashes em caso de vazamento completo da base de dados.

* **Salt Size**: Tamanho da lista de bytes gerada aleatoriamente para que cada hash seja diferente, mesmo com senhas iguais.

* **Hash Size**: Comprimento final em bytes da saída gerada.

> [!WARNING]
> Para que o hash gerado não contenha "=" deve-se usar numeros multiplos de 3
> no Hash size e Salt size, O valor atribuido a eles não representa o tamanho
> da `string` gerada, para prever o tamanho do hash gerado deve-se usar essa formula
> 
>$$
>\text{Resultado} = \frac{\text{Size}}{3} \times 4
>$$
>

* **Memory Cost**: Quantidade de memória RAM exigida para a computação, criando o gargalo que inviabiliza ataques massivos em GPUs, ele trabalha com Kbytes.

> [!WARNING]
> Argon 2 trabalha com Kbytes então deve se atribuir o valor que deseja em Kbytes
>Ex: 250Mb ficaria 256.000Kbytes
>
>$$Kilobytes  = Megabyte \times 1024$$
>

* **Parallelism**: Número de *threads* independentes executadas simultaneamente, ajustando o consumo à arquitetura de concorrência do servidor.

* **Time Cost**: Número de iterações de processamento, definindo o custo de CPU estrito para resolver o cálculo de cada hash.


#### Implementação no .NET

A implementação deve utilizar o [Padrão Options (`IOptions<T>`)](https://learn.microsoft.com/en-us/dotnet/core/extensions/options) da Microsoft para vincular as configurações a objetos de tipagem forte.

Definição estrutural no arquivo `appsettings.json`:

```json
"Argon2IdOptions": {
  "Pepper": "j95mpmza@95u3^yb",
  "SaltSize": 3,
  "HashSize": 9,
  "Parallelism": 2,
  "TimeCost": 4,
  "MemoryCost": 256000
}
```

O vínculo no momento de inicialização utiliza o provedor de [Configuração no .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/configuration) no arquivo `Program.cs`:

```csharp
builder.Services.Configure<Argon2IdOptions>(builder.Configuration.GetSection("Argon2"));
```

Para dados sensíveis como o `Pepper`, é arquiteturalmente incorreto o armazenamento em arquivos físicos no ambiente de produção. O [Gerenciamento Seguro de Segredos de Aplicativos](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets) deve ser aplicado utilizando variáveis de ambiente. O provedor do .NET sobrescreve os dados lendo variáveis estruturadas pelo prefixo `__` (`Argon2__Pepper`).

> [!WARNING]
> **Precedência de Configuração no .NET**
> 
> As variáveis de ambiente **sobrescrevem** os valores do `appsettings.json` devido à hierarquia de provedores do .NET. A última fonte registrada no `IConfiguration` sempre prevalece sobre as anteriores.
>
> **Ordem de Sobrescrita (Padrão):**
> 1. `appsettings.json` (Base)
> 2. `appsettings.{Environment}.json`
> 3. **Secret Manager** (Apenas em `Development`)
> 4. **Variáveis de Ambiente** (Sobrescreve arquivos JSON)
> 5. **Argumentos de Linha de Comando** (Prioridade máxima)
>
> Para detalhes técnicos, consulte a [Documentação Oficial da Microsoft](https://learn.microsoft.com/pt-br/dotnet/core/extensions/configuration).

O serviço criptográfico deve ser encapsulado e registrado no contêiner de [Injeção de Dependência do .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/dependency-injection) para o consumo em outras camadas da aplicação:

```csharp
builder.Services.AddSingleton<Argon2ID>();
```

O uso correto requer a requisição da instância via Injeção de Dependência do .NET diretamente no construtor da classe consumidora, garantindo acesso imediato às funções de encriptação e verificação.

```csharp
//chamar intancia via injeção de dependencia
public class RegisterUser(Argon2ID argon2)
{
  //Criar hash
  string passwordHash = argon2.Encrypt(string rawPassword);
  
  //verificar senha com o hash
  bool pass = argon2.Verify(string rawPassword, string hashPassword);
}
```

### Exemplos de Uso Real

Fluxo de registro de usuário:

```csharp
public class RegisterUserHandler(IUserRepository userRepository, Argon2ID argon2) : IRequestHandler<RegisterUserCommand, Result<RegisterUserResponse>>
{
    public async Task<Result<RegisterUserResponse>> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
    {
        if (await userRepository.ExistsByEmailAsync(request.Email, cancellationToken))
        {
            return Result<RegisterUserResponse>.Failure(RegisterErrors.EmailAlreadyExists);
        }

        string passwordHash = argon2.Encrypt(request.PlainPassword);

        User user = new User(request.Email, passwordHash)
        {
            Id = Uuid.NewSequential()
        };

        user.CreatedBy = request.CreatedBy ?? user.Id;

        await userRepository.CreateAsync(user, cancellationToken);

        return Result<RegisterUserResponse>.Success(new RegisterUserResponse(user.Id, user.FirstName));
    }
}
```

Fluxo de login de usuário:

```csharp
public class EmailLoginUserHandler(IUserRepository userRepository, IJwtProvider jwtProvider, IUserSessionRepository userSessionRepository, Argon2ID argon2) : IRequestHandler<EmailLoginUserCommand, Result<LoginUserResponse>>
{
    public async Task<Result<LoginUserResponse>> Handle(EmailLoginUserCommand request, CancellationToken cancellationToken)
    {
        UserAuthDTO userAuth = await userRepository.GetUserAuthByEmailAsync(request.EmailAddress, request.EmailDomain, cancellationToken);

        if (userAuth is null)
        {
            return Result<LoginUserResponse>.Failure(LoginErrors.UserNotFound);
        }

        if (userAuth.Status != AccountStatus.Active)
        {
            return Result<LoginUserResponse>.Failure(LoginErrors.AccountInactive);
        }

        if (!argon2.Verify(request.Password, userAuth.PasswordHash))
        {
            return Result<LoginUserResponse>.Failure(LoginErrors.InvalidCredentials);
        }

        Guid sessionId = await userSessionRepository.GetSessionIdAsync(userAuth.Id, request.UserAgent.UserAgentComplete, cancellationToken) ?? Uuid.NewSequential();

        string accessToken = await jwtProvider.GenerateAccessTokenAsync(userAuth);
        RefreshToken refreshToken = new(await jwtProvider.GenerateRefreshTokenAsync(), DateTime.UtcNow.AddDays(7));

        if (await userSessionRepository.ExistSessionByIdAsync(sessionId, cancellationToken))
        {
            await userSessionRepository.UpdateRefreshTokenAsync(sessionId, refreshToken, cancellationToken);
        }
        else
        {
            UserSession userSession = new(userAuth.Id, request.UserAgent, refreshToken);
            await userSessionRepository.CreateAsync(userSession, cancellationToken);
        }

        return Result<LoginUserResponse>.Success(new LoginUserResponse(userAuth.Id, userAuth.FirstName, accessToken, refreshToken.Token));
    }
}
```
