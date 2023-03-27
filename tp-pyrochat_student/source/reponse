Réponses au question du TP 
Prise En Main :

1.
La topologie Client / Server en étoile est courante dans de nombreux systèmes informatiques tels que les réseaux de communication, les serveurs de bases de données, les serveurs de messagerie, etc. Elle permet de centraliser les données et de faciliter leur gestion, mais elle peut entraîner des goulets d'étranglement et une saturation du serveur si le nombre de clients est trop important.

2.
Les logs sont un outil essentiel pour le dépannage et la résolution des problèmes dans les systèmes informatiques. En les localisant sur le serveur et en les affichant dans le terminal, il est plus facile de surveiller l'activité du système et de détecter les erreurs et les anomalies.

3.
Le fait que les logs soient en clair et que le Debug soit activé peut être un risque pour la sécurité et la confidentialité des données. En effet, cela peut permettre à des personnes mal intentionnées de récupérer des informations sensibles sur le fonctionnement du système. Il est donc important de prendre des mesures de sécurité pour protéger les logs et les données sensibles.

4.
L'utilisation d'un algorithme de chiffrement symétrique tel que l'AES est une méthode courante pour sécuriser les communications entre deux utilisateurs. Cependant, pour être efficace, il est important de protéger la clé de chiffrement et de s'assurer qu'elle n'est pas interceptée ou compromise. Il existe également d'autres méthodes de chiffrement telles que le chiffrement asymétrique qui utilisent une paire de clés publique/privée pour chiffrer et déchiffrer les données. Ces méthodes peuvent offrir un niveau de sécurité supérieur, mais sont souvent plus complexes à mettre en place.


Chiffrement :

1.
Non, cette fonction n'est pas considérée comme totalement aléatoire, car elle suit une séquence définie. Ainsi, elle peut être prévisible et donc vulnérable à des attaques.

2.
En cryptographie, il est essentiel de bien connaître les primitives que l'on utilise pour pouvoir détecter et corriger toutes les vulnérabilités possibles. Cependant, même en utilisant des primitives éprouvées et testées, il reste une petite probabilité que des vulnérabilités passent inaperçues.


3.
En effet, dans une topologie Client / Server en étoile, un serveur malveillant peut envoyer de faux messages et surcharger le serveur en agissant comme un relais entre les clients. Cela peut entraîner des dysfonctionnements et des pertes de données.


4.
Une étape d'authentification manque dans cette implémentation de chiffrement. Cela peut permettre à un attaquant de se faire passer pour un utilisateur légitime en utilisant des clés volées ou en utilisant une attaque de type "replay". Pour éviter cela, il est recommandé d'utiliser une fonction de hachage sécurisée comme HMAC pour s'assurer que les données sont authentiques et non altérées.


Authenticated Symetric Encryption :

1.
La classe Fernet gère l'ensemble de l'algorithme de chiffrement symétrique avec authentification. Cela inclut la gestion des vecteurs d'initialisation, le chiffrement des messages et l'ajout d'un HMAC pour l'authentification. La méthode de chiffrement implémente également une fonction de durée de vie (TTL) pour empêcher l'utilisation de messages chiffrés après une certaine période de temps.

Le vecteur d'initialisation est automatiquement encodé dans cette implémentation. Cette étape est effectuée dans la méthode "_encrypt_from_parts()" du fichier "fernet.py".

2.
L'attaque par déni de service (DoS) consiste à submerger un serveur de demandes jusqu'à ce qu'il ne soit plus en mesure de traiter les demandes légitimes. Dans le cas de l'authentification symétrique, cela pourrait être réalisé en envoyant un grand nombre de messages chiffrés pour lesquels la clé a expiré.

3.
Pour éviter ce type d'attaque, l'ajout d'un TTL peut être utile. Cette fonction permet de définir une durée de vie maximale pour un message chiffré, empêchant ainsi son utilisation après une certaine période de temps. De cette façon, même si un grand nombre de messages chiffrés sont envoyés, ils seront inutilisables après expiration du TTL.


TTL:

1.
Aucune différence de longueur de message n'est visible en utilisant le TTL, car celui-ci ne modifie pas le contenu du message.

2. 
En retirant 45 secondes du timestamp, le message est considéré comme invalide lors de la vérification du timestamp pendant le déchiffrement. Cette vérification est effectuée pour empêcher les attaques de rejeu, car un attaquant ne peut pas réutiliser le même message avec un timestamp trop éloigné dans le temps. Si l'écart entre le timestamp du message et le temps actuel est supérieur à l'écart maximal autorisé (ici 30 secondes), le déchiffrement échoue.

3.
Il est recommandé de réduire le TTL pour renforcer la sécurité des messages, car en 30 secondes, un attaquant pourrait potentiellement intercepter un message et le retransmettre. Cependant, il est important de trouver un équilibre entre la sécurité et la fiabilité de la communication. Si le TTL est trop court, cela peut entraîner des problèmes de latence et des messages valides peuvent être rejetés, même s'ils ont été envoyés à temps.


Regard critique:

Lors des tests, des messages de petite taille ont été utilisés pour évaluer la sécurité de la librairie Fernet. En effet, la taille des messages reçus peut être une autre vulnérabilité à prendre en compte. Bien que la librairie Fernet soit idéale pour chiffrer des données qui prennent peu de place en mémoire, elle n'est pas adaptée pour les messages trop volumineux.


