
# ⬇️ Vulnérabilités avec snyk.io



## Critique 🔥🔥🔥🔥🔥

### 🔸 1. Utilisation de secrets codés en dur (CWE-798)
Où ? Fichier Docker

### Commentaire :

Présence d’un utilisateur et mot de passe codés en dur dans les variables d’environnement


### 🔸 2. Exposure of Sensitive Information to an Unauthorized Actor (CWE-200)
Où ? Pas encore trouvé (à priori Program.cs ou Controller.cs)

### Commentaire :

Possibilité d'accéder à des ressources du serveur pour lesquelles nous ne sommes pas autorisés, comme par exemple /etc/hosts ou /etc/passwd



## Hautes 🔥🔥🔥

### 🔸 3. Deserialization of Untrusted Data (CWE-502) + Code injection (CWE-94)

Où ? Program.cs - Ligne 91

app.MapGet("/NewEmployee", async (string i) => await Task.FromResult(VLAController.VulnerableDeserialize(HttpUtility.UrlDecode(i)))).WithOpenApi();

### Commentaires :
#### 3.1.
Snyk : Deserialization of Untrusted Data : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Explication : Une donnée non contrôlée (provenant de la requête HTTP) est transmise directement à JsonConvert.DeserializeObject pour être désérialisée. Cela permettrait à un utilisateur malveillant de forger un objet arbitraire pouvant exécuter du code malicieux à la désérialisation.

Recommandation pour les développeurs : N’utilisez jamais JsonConvert.DeserializeObject sur des données provenant de l’utilisateur sans validation stricte du format et du type attendu. Préférez la désérialisation vers des types explicites et limitez l’usage de types dynamiques.


#### 3.2.
Snyk : Code injection : Commentaire : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Explication : La désérialisation de données non sécurisées peut inclure des instructions ou objets capables d’exécuter du code sur le serveur, aboutissant à une injection de code si la configuration ou le type cible est vulnérable.

Recommandation pour les développeurs : Désactivez les fonctionnalités de typage automatique (TypeNameHandling) dans Json.NET, et validez rigoureusement les données entrantes. Évitez les désérialisations sur des types génériques ou inconnus.

-----


### 🔸 4. SSRF (CWE-94) + XXE Injection (CWE-611)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaires :

#### SSRF (Server-Side Request Forgery)
Snyk : Unsanitized input from an HTTP parameter flows into Load, where it is used as an URL to perform a request. This may result in a Server-Side Request Forgery vulnerability.

Explication : L’entrée utilisateur est utilisée comme source de données XML sans contrôle. Cela peut permettre à un attaquant de forcer le serveur à envoyer des requêtes internes ou externes, souvent vers des ressources internes protégées.

Recommandation pour les développeurs : Ne chargez jamais de ressources distantes (URL) depuis une donnée utilisateur. Validez strictement l’entrée et utilisez des parsers XML configurés pour refuser les ressources externes.

#### XXE (XML External Entity)
Snyk : Unsanitized input from an HTTP parameter flows to global::System.Xml.XmlReader.Create. This may result in an XXE vulnerability.

Explication : Le parseur XML peut traiter des entités externes définies dans l’input, ce qui permettrait à un attaquant d’accéder à des fichiers locaux ou de provoquer des requêtes vers des ressources internes.

Recommandation pour les développeurs : Désactivez la résolution des entités externes dans XmlReaderSettings (DtdProcessing = Prohibit) et évitez les DTD dans les données XML entrantes.



## Moyennes 🔥

### 🔸 5. XML Injection (CWE-91)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaire :

Unsanitized input from an HTTP parameter flows into global::System.Xml.XmlReader.Create, where it is used as XML input. This may result in an XML Injection vulnerability.


-----


### 6.Deserialization of Untrusted Data (CWE-502)

Où ? Controller.cs - Ligne 52

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaire :

Using JsonSerializerSettings with TypeNameHandling property set to TypeNameHandling.All, may result in an Unsafe Deserialization vulnerability where it is used to deserialize untrusted object.