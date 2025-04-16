
# ⬇️ Vulnérabilités avec snyk.io

## Critique 🔥🔥🔥🔥🔥

### Utilisation de secrets codés en dur (CWE-798)
Où ? Fichier Docker

### Commentaire :

Présence d’un utilisateur et mot de passe codés en dur dans les variables d’environnement

## Hautes 🔥🔥🔥

### Deserialization of Untrusted Data (CWE-502) + Code injection (CWE-94)

Où ? Program.cs - Ligne 91

app.MapGet("/NewEmployee", async (string i) => await Task.FromResult(VLAController.VulnerableDeserialize(HttpUtility.UrlDecode(i)))).WithOpenApi();

### Commentaires :
Deserialization of Untrusted Data : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.

Code injection : Commentaire : Unsanitized input from an HTTP parameter flows into global::Newtonsoft.Json.JsonConvert.DeserializeObject, where it is used to deserialize an object. This may result in an Unsafe Deserialization vulnerability.


-----


### SSRF (CWE-94) + XXE Injection (CWE-611)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaires :

SSRF : Unsanitized input from an HTTP parameter flows into Load, where it is used as an URL to perform a request. This may result in a Server-Side Request Forgery vulnerability.

XXE Injection : Unsanitized input from an HTTP parameter flows to global::System.Xml.XmlReader.Create. This may result in an XXE vulnerability.


## Moyennes 🔥

### XML Injection (CWE-91)

Où ? Program.cs - Ligne 85

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaire :

Unsanitized input from an HTTP parameter flows into global::System.Xml.XmlReader.Create, where it is used as XML input. This may result in an XML Injection vulnerability.


-----


### Deserialization of Untrusted Data (CWE-502)

Où ? Controller.cs - Ligne 52

app.MapGet("/Contract", async (string i) => await Task.FromResult(VLAController.VulnerableXmlParser(HttpUtility.UrlDecode(i)))).WithOpenApi();


### Commentaire :

Using JsonSerializerSettings with TypeNameHandling property set to TypeNameHandling.All, may result in an Unsafe Deserialization vulnerability where it is used to deserialize untrusted object.