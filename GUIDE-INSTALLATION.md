# Pierre-Olivier Doucet — Comptes clients + espace admin + réservations (TEST)

Cette version ajoute une **vraie base de données centralisée** :
- Les clientes créent un compte (inscription/connexion avec mot de passe), avec vérification d'âge minimum (18 ans)
- Chaque cliente voit son propre historique dans **"Mes rendez-vous"** et peut annuler
- Pierre-Olivier (compte admin) voit **toutes** les réservations de toutes les clientes, peu importe l'appareil utilisé
- Pierre-Olivier peut **gérer entièrement son catalogue de services** depuis l'espace admin : ajouter un nouveau service (jusqu'à 10 actifs), modifier le nom/la durée/le prix/la description de chacun, et désactiver un service qu'elle ne souhaite plus offrir
- **Nouveau : Pierre-Olivier gère elle-même ses disponibilités** — heures d'ouverture par jour de la semaine, et blocages ponctuels (jour complet ou plage d'heures précise) pour ses vacances, congés, ou rendez-vous personnels
- "Mot de passe oublié" fonctionnel, avec lien de réinitialisation envoyé par courriel
- **Nouveau : rappel automatique par courriel 24h avant chaque rendez-vous confirmé** — aucune action de Pierre-Olivier n'est requise, le serveur vérifie lui-même toutes les 15 minutes
- Un courriel de confirmation est envoyé (via Resend) à chaque réservation
- Pas de paiement réel pour cette version — seul le virement Interac est proposé, et Pierre-Olivier confirme manuellement la réservation depuis l'espace admin une fois le virement reçu

---

## 1. Installer Node.js

Si nécessaire : https://nodejs.org (version LTS). Vérifiez avec :
```
node --version
npm --version
```

---

## 2. Créer votre compte Resend (envoi d'email)

1. Compte gratuit sur https://resend.com
2. Dans **API Keys**, cliquez **Create API Key** et copiez la clé (commence par `re_...`)
3. Par défaut, vous pouvez envoyer depuis `onboarding@resend.dev` sans configuration supplémentaire (parfait pour les tests)

---

## 3. Configurer le projet

1. Dans le dossier `pierre-olivier-doucet-fullstack`, dupliquez `.env.example` en `.env`
2. Remplissez :

```
RESEND_API_KEY=re_...........(votre clé Resend)
EMAIL_FROM=onboarding@resend.dev
ADMIN_EMAIL=contact@3pierre6olivier9.com
ADMIN_PASSWORD=choisissez-un-mot-de-passe-solide
SESSION_SECRET=une-longue-chaine-aleatoire-unique
PORT=3000
```

**Important** : `ADMIN_EMAIL` et `ADMIN_PASSWORD` créent automatiquement le compte de Pierre-Olivier au premier démarrage. C'est avec ce courriel et ce mot de passe que Pierre-Olivier se connectera pour voir toutes les réservations.

---

## 4. Installer et démarrer

```
npm install
npm start
```

Vous devriez voir :
```
✦ Compte admin créé : contact@3pierre6olivier9.com (mot de passe défini dans .env -> ADMIN_PASSWORD)
✦ Serveur Pierre-Olivier Doucet (TEST) démarré : http://localhost:3000
```

Ouvrez **http://localhost:3000**.

---

## 5. Tester le parcours complet

### Comme cliente
1. **Inscription** : créez un compte avec votre nom, courriel, mot de passe (6 caractères minimum)
2. **Réserver maintenant** : choisissez un service, une date, une heure
3. Choisissez "Carte bancaire" ou "Virement Interac" (aucun paiement réel n'est demandé dans cette version)
4. Confirmez : vous recevrez un email de confirmation (vérifiez vos courriels, et le dossier spam)
5. Allez dans **"Mes rendez-vous"** : votre réservation apparaît, avec la possibilité de l'annuler

### Comme Pierre-Olivier (admin)
1. Déconnectez-vous, puis connectez-vous avec l'adresse `ADMIN_EMAIL` et le mot de passe `ADMIN_PASSWORD` définis dans `.env`
2. Un bouton **"Admin"** apparaît dans le menu — cliquez dessus
3. Vous voyez **toutes** les réservations de toutes les clientes, avec leur nom et courriel
4. Vous pouvez cliquer "Confirmer" (passe le statut à confirmé) ou "Annuler" sur chaque réservation
5. Plus bas sur la même page, dans **"Gestion des services"** :
   - En haut, le formulaire **"Ajouter un nouveau service"** permet de créer un service (nom, durée, description, prix) — le bouton se désactive automatiquement une fois 10 services actifs atteints
   - Chaque service existant affiche son statut (**ACTIF** / **DÉSACTIVÉ**) et peut être modifié (nom, durée, description, prix) puis enregistré
   - Le bouton **"Désactiver"** retire un service du site (il ne sera plus proposé aux nouvelles réservations) sans effacer l'historique des rendez-vous déjà pris avec ce service ; le bouton **"Réactiver"** permet de le remettre en ligne plus tard
6. Encore plus bas, dans **"Disponibilités"** :
   - Réglez vos **heures d'ouverture habituelles** pour chaque jour de la semaine (décochez un jour pour le fermer complètement, ex. le dimanche)
   - **Bloquez une date précise** : laissez les heures de début/fin vides pour bloquer la journée complète (vacances), ou indiquez une plage (ex. 9h-12h) pour ne fermer que cette partie de la journée
   - Les blocages à venir apparaissent dans la liste juste en dessous, avec un bouton **"Retirer"** si vous changez d'avis

**Important à savoir sur la gestion des services :**
- **10 services actifs maximum** à la fois (limite affichée en haut de la section, ex. "4 / 10 services actifs"). Pour ajouter un 11ᵉ service, il faut d'abord en désactiver un.
- Un changement de nom, durée, prix ou description ne s'applique qu'aux **nouvelles réservations** faites après la modification
- Désactiver un service ne supprime rien : les rendez-vous déjà réservés gardent en mémoire le nom et le prix du service tels qu'ils étaient au moment de la réservation — rien ne change rétroactivement pour une cliente qui a déjà réservé
- Les changements (ajout, modification, désactivation) apparaissent immédiatement sur le site (page d'accueil, page Services, étape 1 de la réservation)

### Vérifier que les créneaux sont bien partagés
Ouvrez le site dans deux navigateurs différents (ou un onglet normal + un onglet privé), créez deux comptes différents, et réservez le même service à la même date. Le deuxième compte ne verra plus l'heure déjà prise par le premier dans la liste des créneaux disponibles.

### À propos des rappels automatiques
- Le serveur vérifie **toutes les 15 minutes** s'il y a des rendez-vous **confirmés** dont l'heure approche dans environ 24h, et envoie alors un courriel de rappel à la cliente.
- Seuls les rendez-vous au statut **« confirmé »** reçoivent un rappel — un rendez-vous encore « en attente » de virement n'en reçoit pas.
- Le rappel n'est envoyé **qu'une seule fois** par rendez-vous (même si le serveur redémarre plusieurs fois).
- Pour le tester rapidement sans attendre 24h, vous pouvez modifier temporairement la date d'une réservation directement dans la base de données (`data/pierreolivierdoucet.db`, table `bookings`, colonne `booking_date`) pour qu'elle tombe dans la fenêtre des prochaines 24h, puis attendre la prochaine vérification (jusqu'à 15 minutes) ou redémarrer le serveur — une vérification se déclenche aussi 10 secondes après chaque démarrage.
- **Important** : si l'ordinateur de Pierre-Olivier est éteint ou le serveur arrêté au moment où un rappel aurait dû partir, il sera tout de même envoyé dès le prochain démarrage, pourvu que le rendez-vous ne soit pas encore passé.

---

## 6. Limites de cette version TEST

- **Pas de paiement réel.** Pour ajouter Stripe par-dessus ce système de comptes, on peut reprendre l'intégration de la version précédente et y ajouter la vérification du compte connecté.
- **Local uniquement.** Le serveur tourne sur votre machine ; pour que de vraies clientes y accèdent depuis chez elles, il faudra le déployer en ligne (Render, Railway, etc.) — je peux vous accompagner pour cette étape.
- **Domaine email non vérifié.** Avec `onboarding@resend.dev`, certains clients de messagerie peuvent classer l'email en indésirables. Vérifier votre propre domaine dans Resend améliore cela.
- **Sécurité de base uniquement.** Les mots de passe sont correctement hashés (bcrypt) et les sessions sont sécurisées par cookie signé, ce qui est suffisant pour un test, mais avant une mise en ligne réelle avec de vraies clientes, je recommande une revue de sécurité plus complète (HTTPS obligatoire, limitation du taux de tentatives de connexion, etc.).

---

## Prochaines étapes possibles

- Réintégrer Stripe (mode test, puis mode production) par-dessus ce système de comptes
- Déployer en ligne pour un test avec de vraies utilisatrices
- Ajouter "mot de passe oublié"
- Personnaliser davantage l'espace admin (filtres par date, export, statistiques)

Dites-moi simplement par lequel vous souhaitez continuer.
