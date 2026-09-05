// ============================================================
// Serveur de TEST — Pierre-Olivier Doucet
// Comptes clients + espace admin + réservations + email
// ============================================================
// Démarrage : npm install puis npm start
// ============================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookieSession = require('cookie-session');
const Database = require('better-sqlite3');
const { Resend } = require('resend');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.RESEND_API_KEY) {
  console.warn('\n⚠️  RESEND_API_KEY manquant dans .env — les emails ne seront pas envoyés.\n');
}

const resend = new Resend(process.env.RESEND_API_KEY || 're_placeholder');

// ---------- Base de données SQLite ----------
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const db = new Database(path.join(dataDir, 'pierreolivierdoucet.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    birth_date TEXT,
    city TEXT,
    role TEXT NOT NULL DEFAULT 'client', -- 'client' ou 'admin'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    service_price_cents INTEGER NOT NULL,
    booking_date TEXT NOT NULL,       -- format AAAA-MM-JJ
    booking_date_label TEXT NOT NULL, -- format affichable
    booking_time TEXT NOT NULL,
    payment_method TEXT NOT NULL,     -- 'carte' ou 'interac'
    status TEXT NOT NULL DEFAULT 'en_attente', -- en_attente / confirme / annule / propose
    reminder_sent_at TEXT,            -- NULL = rappel pas encore envoyé
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- Rendez-vous proposé par l'admin (nouveau rendez-vous pris pour la cliente,
    -- ou report d'un rendez-vous existant) : la cliente doit Accepter/Refuser via
    -- un lien sécurisé à usage unique envoyé par courriel. accept_token_hash ne
    -- stocke jamais le jeton en clair (seulement son empreinte SHA-256), comme
    -- pour les jetons de réinitialisation de mot de passe.
    accept_token_hash TEXT,
    accept_token_expires_at TEXT,
    previous_status TEXT,             -- statut à réappliquer si la cliente accepte
    responded_at TEXT,                -- NULL = en attente de réponse de la cliente
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    duration TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price_cents INTEGER NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS blocked_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL DEFAULT 'age_minimum_non_respecte',
    blocked_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS testimonials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL DEFAULT 5,     -- de 1 à 5
    quote TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'en_attente', -- en_attente / approuve / rejete
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- Système de conversation entre une cliente connectée et Pierre-Olivier.
  -- Une seule conversation continue par client : tous les échanges (questions,
  -- réponses de Pierre-Olivier) restent dans le même fil, classé par ordre chronologique.
  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    has_unread_for_admin INTEGER NOT NULL DEFAULT 1, -- 1 = Pierre-Olivier a un nouveau message non lu
    has_unread_for_client INTEGER NOT NULL DEFAULT 0, -- 1 = le client a une réponse non lue
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- Chaque message individuel dans une conversation.
  CREATE TABLE IF NOT EXISTS conversation_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender TEXT NOT NULL, -- 'client' ou 'admin'
    message TEXT NOT NULL,
    email_sent INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (conversation_id) REFERENCES conversations(id)
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- Textes modifiables des pages publiques (Accueil et À propos), édités
  -- par Pierre-Olivier depuis l'espace admin sans intervention du développeur.
  -- Clé-valeur simple : chaque "key" correspond à un bloc de texte précis
  -- (voir SITE_CONTENT_DEFAULTS plus bas pour la liste complète et les
  -- valeurs par défaut au premier démarrage).
  CREATE TABLE IF NOT EXISTS site_content (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Registre des consentements à la collecte de renseignements personnels
  -- (Loi 25 du Québec / PIPEDA). Un enregistrement est créé à chaque
  -- inscription, et conservé même si le compte est supprimé plus tard,
  -- pour constituer une preuve de consentement horodatée.
  CREATE TABLE IF NOT EXISTS consent_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,              -- peut être NULL si le compte est supprimé ensuite
    email TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    ip_address TEXT,
    accepted_at TEXT NOT NULL DEFAULT (datetime('now')),
    withdrawn_at TEXT              -- NULL = consentement toujours actif
  );

  -- Journal d'audit des suppressions de données (Loi 25 / PIPEDA) : garde
  -- une trace minimale (sans renseignements personnels identifiables) de
  -- chaque suppression automatique ou volontaire, pour pouvoir démontrer
  -- la conformité en cas de vérification.
  CREATE TABLE IF NOT EXISTS data_retention_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,      -- 'account_auto_deleted' / 'account_self_deleted' / 'bookings_purged'
    detail TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Heures d'ouverture par défaut, une ligne par jour de la semaine (0 = dimanche ... 6 = samedi).
  -- "is_open" = 0 signifie que ce jour est fermé par défaut (ex : dimanche).
  CREATE TABLE IF NOT EXISTS business_hours (
    weekday INTEGER PRIMARY KEY CHECK (weekday BETWEEN 0 AND 6),
    is_open INTEGER NOT NULL DEFAULT 1,
    start_time TEXT NOT NULL DEFAULT '09:00',
    end_time TEXT NOT NULL DEFAULT '17:00',
    slot_duration_minutes INTEGER NOT NULL DEFAULT 30,
    break_between_slots_minutes INTEGER NOT NULL DEFAULT 0,
    break_start TEXT,
    break_end TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Blocages ponctuels créés par Pierre-Olivier : un jour complet (start_time/end_time
  -- vides) ou une plage d'heures précise sur une date donnée (ex: vacances,
  -- rendez-vous personnel, fermeture exceptionnelle).
  CREATE TABLE IF NOT EXISTS blocked_periods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocked_date TEXT NOT NULL,   -- format AAAA-MM-JJ
    start_time TEXT,              -- NULL = jour complet bloqué
    end_time TEXT,                -- NULL = jour complet bloqué
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Images modifiables des pages publiques (remplace les emplacements
  -- « Image à venir »), éditées par Pierre-Olivier depuis l'espace admin.
  -- Stockées directement en base (en base64) pour rester cohérent avec le
  -- reste du site, qui embarque déjà toutes ses images de cette façon.
  CREATE TABLE IF NOT EXISTS site_images (
    key TEXT PRIMARY KEY,
    mime_type TEXT NOT NULL,
    data_base64 TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Parcours d'accompagnement sur plusieurs séances (3 mois / 6 mois / Parent & Enfant).
  -- Un parcours regroupe plusieurs lignes de la table "bookings" (une par séance)
  -- sous un même suivi de progression. La progression (séances complétées, à venir,
  -- annulées) n'est PAS stockée ici : elle est toujours recalculée en direct à partir
  -- des réservations liées (program_id), pour qu'il n'y ait jamais de donnée périmée.
  CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_id INTEGER,
    service_name TEXT NOT NULL,
    total_appointments INTEGER NOT NULL,
    program_status TEXT NOT NULL DEFAULT 'actif', -- actif / termine / annule
    start_date TEXT NOT NULL DEFAULT (date('now')),
    end_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Migration légère : ajout des colonnes liées aux parcours multi-séances sur
// les tables déjà existantes (services, bookings), sans perdre les données.
const serviceColumns = db.prepare("PRAGMA table_info(services)").all().map(c => c.name);
if (!serviceColumns.includes('is_program')) {
  db.exec("ALTER TABLE services ADD COLUMN is_program INTEGER NOT NULL DEFAULT 0");
}
if (!serviceColumns.includes('program_sessions')) {
  db.exec("ALTER TABLE services ADD COLUMN program_sessions INTEGER");
}

const bookingColumnsForPrograms = db.prepare("PRAGMA table_info(bookings)").all().map(c => c.name);
if (!bookingColumnsForPrograms.includes('program_id')) {
  db.exec("ALTER TABLE bookings ADD COLUMN program_id INTEGER REFERENCES programs(id)");
}
if (!bookingColumnsForPrograms.includes('program_seq')) {
  db.exec("ALTER TABLE bookings ADD COLUMN program_seq INTEGER");
}

// Migration légère : si la base existait déjà avant l'ajout de birth_date,
// on ajoute la colonne sans perdre les données existantes.
const userColumns = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userColumns.includes('birth_date')) {
  db.exec('ALTER TABLE users ADD COLUMN birth_date TEXT');
}
if (!userColumns.includes('city')) {
  db.exec('ALTER TABLE users ADD COLUMN city TEXT');
}
if (!userColumns.includes('phone')) {
  db.exec('ALTER TABLE users ADD COLUMN phone TEXT');
}
if (userColumns.includes('synced_from_app')) {
  // Colonne héritée de l'intégration Sync7up (retirée du site) : on la
  // supprime pour ne garder aucune trace de cette synchronisation.
  db.exec("ALTER TABLE users DROP COLUMN synced_from_app");
}
if (!userColumns.includes('last_activity_at')) {
  // Mise à jour à chaque connexion réussie. Sert à détecter l'inactivité
  // (Loi 25 / PIPEDA) pour l'avertissement puis la suppression automatique
  // des comptes clients inactifs. Initialisée à la date de création pour
  // les comptes déjà existants, afin de ne pas tous les marquer "inactifs
  // depuis toujours" dès l'activation de cette fonctionnalité.
  db.exec("ALTER TABLE users ADD COLUMN last_activity_at TEXT");
  db.exec("UPDATE users SET last_activity_at = created_at WHERE last_activity_at IS NULL");
}
if (!userColumns.includes('inactivity_warning_sent_at')) {
  // NULL = aucun avertissement envoyé pour la période d'inactivité en cours.
  // Remis à NULL automatiquement dès que le compte redevient actif.
  db.exec("ALTER TABLE users ADD COLUMN inactivity_warning_sent_at TEXT");
}

const bookingColumns = db.prepare("PRAGMA table_info(bookings)").all().map(c => c.name);
if (!bookingColumns.includes('reminder_sent_at')) {
  db.exec('ALTER TABLE bookings ADD COLUMN reminder_sent_at TEXT');
}
if (bookingColumns.includes('sync7up_external_id')) {
  // Colonnes héritées de l'intégration Sync7up (retirée du site).
  db.exec('ALTER TABLE bookings DROP COLUMN sync7up_external_id');
}
if (bookingColumns.includes('sync7up_synced_at')) {
  db.exec('ALTER TABLE bookings DROP COLUMN sync7up_synced_at');
}
if (!bookingColumns.includes('accept_token_hash')) {
  db.exec('ALTER TABLE bookings ADD COLUMN accept_token_hash TEXT');
}
if (!bookingColumns.includes('accept_token_expires_at')) {
  db.exec('ALTER TABLE bookings ADD COLUMN accept_token_expires_at TEXT');
}
if (!bookingColumns.includes('previous_status')) {
  db.exec('ALTER TABLE bookings ADD COLUMN previous_status TEXT');
}
if (!bookingColumns.includes('responded_at')) {
  db.exec('ALTER TABLE bookings ADD COLUMN responded_at TEXT');
}

// Migration légère : pause configurable entre les créneaux (ajoutée après
// la première version de business_hours).
const businessHoursColumns = db.prepare("PRAGMA table_info(business_hours)").all().map(c => c.name);
if (!businessHoursColumns.includes('break_between_slots_minutes')) {
  db.exec('ALTER TABLE business_hours ADD COLUMN break_between_slots_minutes INTEGER NOT NULL DEFAULT 0');
}

// Migration : la fonctionnalité de bannière promotionnelle a été retirée du
// site. Si une base de données existante contient encore l'ancienne table
// (et ses éventuelles images), on la supprime proprement une seule fois,
// sans jamais faire échouer le démarrage si elle est déjà absente.
try {
  db.exec('DROP TABLE IF EXISTS promo_banner');
} catch (err) {
  console.error('Erreur lors du retrait de l\'ancienne table promo_banner :', err.message);
}

// ---------- Heures d'ouverture : seed initial (une seule fois) ----------
// Par défaut : ouvert lundi à samedi 9h-17h, fermé le dimanche.
// Reproduit l'ancien comportement codé en dur côté client (isSunday = fermé).
function ensureBusinessHoursSeed() {
  const count = db.prepare('SELECT COUNT(*) as n FROM business_hours').get().n;
  if (count > 0) return;
  const insert = db.prepare(`
    INSERT INTO business_hours (weekday, is_open, start_time, end_time, slot_duration_minutes)
    VALUES (?, ?, ?, ?, ?)
  `);
  for (let weekday = 0; weekday <= 6; weekday++) {
    const isOpen = weekday !== 0; // 0 = dimanche
    insert.run(weekday, isOpen ? 1 : 0, '09:00', '17:00', 30);
  }
  console.log('✦ Heures d\'ouverture par défaut initialisées (fermé le dimanche).');
}
ensureBusinessHoursSeed();

// ---------- Catalogue des services : seed initial (une seule fois) ----------
// Important : la base de données est désormais la source de vérité.
// Ce tableau ne sert qu'à peupler la table "services" la toute première fois
// que le serveur démarre (si la table est vide). Toute modification ultérieure
// se fait via l'espace admin et est enregistrée en base.
const DEFAULT_SERVICES = [
  { name: 'Rencontre Découverte', duration: '30 min', priceCents: 4000, description: "Un premier moment d'écoute pour se rencontrer, clarifier votre besoin du moment et voir ensemble ce qui pourrait vous convenir." },
  { name: 'Rencontre Approfondie', duration: '90 min', priceCents: 9000, description: 'Un espace plus long pour explorer en profondeur une situation, un questionnement ou une période de transition.' },
];

function ensureServicesSeed() {
  const count = db.prepare('SELECT COUNT(*) as n FROM services').get().n;
  if (count > 0) return;
  const insert = db.prepare(`
    INSERT INTO services (sort_order, name, duration, description, price_cents, active)
    VALUES (?, ?, ?, ?, ?, 1)
  `);
  DEFAULT_SERVICES.forEach((s, i) => insert.run(i, s.name, s.duration, s.description, s.priceCents));
  console.log(`✦ Catalogue des services initialisé (${DEFAULT_SERVICES.length} services).`);
}
ensureServicesSeed();

// ---------- Catalogue des services : accompagnements personnalisés ----------
// Ajoutés séparément (et de façon idempotente, par nom) afin de fonctionner
// aussi bien sur une base de données neuve que sur une base déjà en place où
// ensureServicesSeed() ci-dessus ne s'exécute plus (table déjà non vide).
const ACCOMPAGNEMENT_SERVICES = [
  {
    name: 'Accompagnement Personnalisé — 75 minutes',
    duration: '75 min',
    priceCents: 13300,
    description: "Espace personnalisé permettant d'explorer les questionnements, blocages, émotions, relations, transitions et situations actuelles. L'objectif est d'aider la personne à observer ce qui se présente, retrouver ses propres repères et avancer avec davantage de conscience.",
  },
  {
    name: 'Accompagnement Personnalisé — 3 mois',
    duration: '3 mois',
    priceCents: 111100,
    description: "Parcours permettant un accompagnement dans la durée afin d'observer le cheminement, intégrer les prises de conscience et approfondir la compréhension de soi. Explore notamment les schémas répétitifs, les relations, les émotions, les transitions, le fonctionnement personnel, ainsi que de nouvelles façons d'avancer.",
  },
  {
    name: 'Accompagnement Personnalisé — 6 mois',
    duration: '6 mois',
    priceCents: 222200,
    description: "Parcours approfondi permettant davantage de continuité, de réflexion, d'intégration et de compréhension. L'objectif est de favoriser l'autonomie, le discernement et la confiance envers son propre chemin.",
  },
  {
    name: 'Accompagnement Parent & Enfant — 3 mois',
    duration: '3 mois',
    priceCents: 66600,
    description: "Accompagnement destiné aux parents souhaitant mieux comprendre leur relation avec leur enfant, développer leur écoute et observer autrement les besoins, réactions, émotions et modes d'expression de l'enfant. Explore la sensibilité de l'enfant, la communication, les besoins, la relation parent-enfant, l'environnement, les émotions du parent, la présence, l'écoute et l'observation.",
  },
];

function ensureAccompagnementServicesSeed() {
  const existingNames = new Set(db.prepare('SELECT name FROM services').all().map((r) => r.name));
  const maxOrder = db.prepare('SELECT COALESCE(MAX(sort_order), -1) as m FROM services').get().m;
  const insert = db.prepare(`
    INSERT INTO services (sort_order, name, duration, description, price_cents, active)
    VALUES (?, ?, ?, ?, ?, 1)
  `);
  let nextOrder = maxOrder + 1;
  let added = 0;
  ACCOMPAGNEMENT_SERVICES.forEach((s) => {
    if (existingNames.has(s.name)) return; // déjà présent (ex : ajouté manuellement ou lors d'un run précédent)
    insert.run(nextOrder, s.name, s.duration, s.description, s.priceCents);
    nextOrder += 1;
    added += 1;
  });
  if (added > 0) console.log(`✦ ${added} accompagnement(s) personnalisé(s) ajouté(s) au catalogue.`);
}
ensureAccompagnementServicesSeed();

// Marque les services "parcours" (plusieurs séances sur la durée) afin que le
// système de suivi de progression sache combien de rendez-vous ils comportent.
// Idempotent et basé sur le nom : peut être relancé sans effet si déjà en place,
// et n'écrase jamais un réglage déjà personnalisé par Pierre-Olivier.
const PROGRAM_SESSIONS_BY_SERVICE_NAME = {
  'Accompagnement Personnalisé — 3 mois': 6,
  'Accompagnement Personnalisé — 6 mois': 12,
  'Accompagnement Parent & Enfant — 3 mois': 6,
};
function ensureProgramServicesMigration() {
  const update = db.prepare(`UPDATE services SET is_program = 1, program_sessions = ? WHERE name = ? AND (is_program = 0 OR program_sessions IS NULL)`);
  let updated = 0;
  for (const [name, sessions] of Object.entries(PROGRAM_SESSIONS_BY_SERVICE_NAME)) {
    const result = update.run(sessions, name);
    updated += result.changes;
  }
  if (updated > 0) console.log(`✦ ${updated} service(s) marqué(s) comme parcours multi-séances.`);
}
ensureProgramServicesMigration();

// ---------- Textes modifiables (Accueil + À propos) : seed initial ----------
// Reprend exactement les textes codés en dur dans public/index.html au moment
// de la mise en place de cette fonctionnalité, pour qu'aucun changement
// visuel n'apparaisse tant que Pierre-Olivier n'a rien modifié elle-même.
const SITE_CONTENT_DEFAULTS = {
  // --- Page Accueil : bloc principal (hero) ---
  home_eyebrow: '✦ Écoute &amp; Accompagnement',
  home_title: 'Pierre-Olivier Doucet',
  home_tagline: 'Écoute &amp; Accompagnement',
  home_desc: 'Un espace d\'écoute et d\'accompagnement personnalisé pour cheminer avec davantage de clarté et de conscience de soi.',
  // --- Page Accueil : section "Mon approche" ---
  home_approach_eyebrow: 'Mon approche',
  home_approach_title: 'Un espace humain pour revenir à soi',
  home_approach_p1: "Depuis plusieurs années, j'accompagne avec douceur les personnes en quête de sens, de clarté et de compréhension d'elles-mêmes. Mon approche s'appuie sur l'écoute, la présence et le respect du rythme de chacun.",
  home_approach_p2: 'Chaque séance est un moment unique, entièrement adapté à votre chemin, dans un cadre bienveillant et sans jugement.',
  home_quote: "« Mon intention est de vous offrir un espace sacré où votre intuition peut s'exprimer librement. »",
  // --- Page Accueil : en-têtes des sections suivantes ---
  home_services_eyebrow: 'Mes services',
  home_services_title: 'Des séances pensées pour vous',
  home_services_desc: 'Que vous cherchiez une réponse rapide ou un accompagnement plus profond, chaque service est conçu pour répondre à votre besoin du moment.',
  home_testimonials_eyebrow: 'Témoignages',
  home_testimonials_title: 'Ce que partagent les personnes accompagnées',
  home_faq_eyebrow: 'Questions fréquentes',
  home_faq_title: "Tout ce qu'il faut savoir",
  home_faq_cta: 'Voir toutes les questions',

  // --- Page Accueil : blocs alternés (texte + image) ---
  home_cta1: 'Réserver maintenant →',
  home_cta2: 'Découvrir les services',
  home_block1_title: '✦ Créer un espace où tu peux être pleinement toi',
  home_block1_text: `<p class="prose-body" style="margin-top:14px;max-width:none;">Dans mes accompagnements, il n'est pas nécessaire de porter un masque, de prétendre que tout va bien ou de correspondre à ce que les autres attendent de toi.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Je t'offre un espace où tu peux déposer ce qui pèse, mettre des mots sur ce qui est difficile à comprendre et prendre du recul sur certaines situations.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Mon rôle n'est pas de vivre ton chemin à ta place.<br>Il est de marcher à tes côtés suffisamment longtemps pour que tu puisses retrouver ta propre direction.</p>`,
  home_block2_title: '✦ Comprendre plutôt que fuir',
  home_block2_text: `<p class="prose-body" style="margin-top:14px;max-width:none;">Certaines situations reviennent dans notre vie parce qu'elles cherchent à nous montrer quelque chose.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Une relation, une peur, un blocage, une répétition, une perte de repères ou une période de transformation peuvent devenir des occasions de mieux comprendre notre fonctionnement et nos choix.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Je t'invite donc à ne pas seulement chercher à faire disparaître ce qui dérange, mais à comprendre ce que cette expérience vient révéler.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Parce que lorsque nous comprenons réellement ce qui se joue en nous, notre façon de regarder la vie peut commencer à changer.</p>`,
  home_block3_title: '✦ Authenticité, transparence et honnêteté',
  home_block3_text: `<p class="prose-body" style="margin-top:14px;max-width:none;">Trois valeurs sont au cœur de mon approche :</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;"><strong>Authenticité.</strong> Être capable de rencontrer ce qui est réellement présent, sans chercher à jouer un rôle.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;"><strong>Transparence.</strong> Pouvoir communiquer librement, clairement et sans créer d'illusions.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;"><strong>Honnêteté.</strong> Avoir le courage de regarder les choses avec lucidité, même lorsque ce que l'on découvre n'est pas nécessairement ce que l'on voulait entendre.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Je crois que c'est dans cet espace que peut naître une véritable évolution.</p>`,
  home_block4_title: '✦ Ton chemin reste le tien',
  home_block4_text: `<p class="prose-body" style="margin-top:14px;max-width:none;">Je ne suis pas là pour prendre tes décisions à ta place, te dicter une direction ou créer une dépendance à l'accompagnement.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Je souhaite plutôt t'aider à développer ton propre regard, à reprendre contact avec tes ressources et à retrouver suffisamment de clarté pour avancer par toi-même.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Il n'existe pas de chemin parfait.<br>Il existe ton chemin.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Et parfois, il suffit simplement d'avoir quelqu'un à nos côtés pour nous aider à voir ce que nous étions incapables de voir seuls.</p>
            <p class="prose-body" style="margin-top:20px;max-width:none;font-style:italic;">Mon approche est avant tout une rencontre humaine.<br>Une rencontre avec soi, avec ce qui est présent aujourd'hui et avec ce qui demande maintenant à évoluer.</p>`,

  // --- Page Parcours/Valeurs : en-tête (non utilisé dans la mise en page actuelle) ---
  about_eyebrow: 'Mon histoire',
  about_title: 'À propos de Pierre-Olivier Doucet',

  // --- Page Parcours/Valeurs : section 1 « Mon parcours » ---
  about_p1_eyebrow: 'Mon parcours',
  about_p1_title: "Un parcours qui a commencé tôt, fait d'écoute et d'exploration",
  about_p1_text: `<p class="prose-body" style="margin-top:20px;max-width:none;">Certaines portes se sont ouvertes très tôt dans mon existence. À l'âge de 7 ans, je vivais déjà des expériences que je percevais comme sortant de l'ordinaire. Je ne savais pas nécessairement comment les comprendre à l'époque, mais elles ont marqué quelque chose en moi et ont ouvert progressivement un espace de questionnement autour de la conscience et de l'expérience humaine.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Plus tard, durant mes années au secondaire, mon intérêt s'est naturellement tourné vers l'être humain. Je me suis intéressé au langage non verbal, aux émotions, aux comportements et aux messages subtils exprimés par le corps. J'étais déjà animé par cette envie de comprendre ce qui se trouve derrière les apparences : qu'est-ce qu'une personne exprime réellement, que raconte son corps, que se passe-t-il derrière les mots ?</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Au fil de mon parcours, j'ai continué à explorer différentes dimensions de l'être humain. Je n'ai jamais considéré mon chemin comme une ligne droite. Il a plutôt ressemblé à une succession d'expériences qui m'ont chacune apporté quelque chose : certaines m'ont rapproché de moi-même, d'autres m'ont obligé à remettre en question ce que je croyais savoir, certaines m'ont confronté à mes propres limites, et d'autres m'ont appris à écouter davantage.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Avec le temps, j'ai compris que nous sommes constamment en train de nous rencontrer nous-mêmes à travers ce que nous vivons. Nos expériences nous façonnent, nos choix nous enseignent, nos relations nous révèlent certaines parties de nous, et nos épreuves peuvent parfois devenir des passages vers une compréhension plus profonde de qui nous sommes.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">J'ai moi-même traversé des périodes de profonde transformation, des moments où certaines structures de ma vie ont dû être entièrement repensées. J'ai connu ce que j'appelle personnellement une « nuit noire de l'âme », une période où l'obscurité semble parfois prendre davantage de place que la lumière. Mais avec le recul, j'ai compris que certaines traversées peuvent aussi nous inviter à revenir vers ce qui est véritablement essentiel.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">À travers mes expériences et les personnes que la vie a placées sur mon chemin, j'ai progressivement appris à reprendre ma responsabilité, mon pouvoir intérieur et ma souveraineté personnelle. Non pas une souveraineté sur les autres, mais une souveraineté sur moi-même : la capacité de reconnaître ce qui m'appartient, de faire mes choix, de reprendre ma place et d'écouter ce qui résonne profondément en moi.</p>`,

  // --- Page Parcours/Valeurs : section 2 « Ne pas se limiter à une définition » ---
  about_p2_title: '✦ Ne pas se limiter à une définition',
  about_p2_text: `<p class="prose-body" style="margin-top:14px;max-width:none;">Je n'aime pas m'identifier à une étiquette ou à un titre.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Parce qu'au fond, se définir par une seule appellation pourrait parfois devenir une forme de limitation.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">J'aime davantage l'idée de pouvoir être <strong>tout à la fois</strong>, plutôt que de ne représenter qu'une seule partie de ce que je suis.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Je ne souhaite pas être enfermé dans une définition, une fonction ou une identité précise.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Ma plus belle découverte à travers tout ce parcours est justement cette compréhension de ce que j'appelle <strong>le multidimensionnel</strong>.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Découvrir qu'il peut exister plusieurs facettes de soi, plusieurs niveaux d'expérience, plusieurs façons de percevoir et de comprendre notre réalité.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Pour moi, le chemin n'est donc pas de choisir une seule partie de soi et d'en faire une identité.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">C'est plutôt d'apprendre à <strong>reconnaître, accueillir et harmoniser les différentes parties qui nous composent.</strong></p>`,

  // --- Page Parcours/Valeurs : section 3 « Observer, expérimenter et comprendre » ---
  about_p3_title: '✦ Observer, expérimenter et comprendre',
  about_p3_text: `<p class="prose-body" style="margin-top:14px;max-width:none;">Avec tout ce chemin parcouru, une chose est devenue de plus en plus importante pour moi :</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;"><strong>ne pas croire simplement parce que quelqu'un nous dit de croire.</strong></p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Observer. Expérimenter. Questionner. Ressentir. Comprendre.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Mon parcours ne se résume donc pas à des formations, à des expériences ou à ce que certains pourraient appeler des « dons ».</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Il représente avant tout un <strong>chemin d'exploration personnelle</strong>, avec ses découvertes, ses remises en question, ses apprentissages et ses zones d'ombre.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Et plus j'avance, plus je comprends que chaque personne que nous rencontrons peut devenir, à certains moments, <strong>la lumière ou l'ombre de notre propre chemin</strong>.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Certaines personnes nous montrent ce que nous sommes prêts à accueillir.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">D'autres nous révèlent ce que nous avons encore à comprendre.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Certaines nous élèvent.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">D'autres nous confrontent.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Et parfois, les deux jouent exactement le même rôle : <strong>nous faire avancer.</strong></p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">C'est pourquoi je crois profondément que tout a une raison d'être.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Pas nécessairement parce que tout doit être accepté sans discernement, mais parce que chaque expérience peut devenir une occasion d'observer, de comprendre, d'intégrer et de grandir.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Aujourd'hui, mon intention n'est pas de me placer au-dessus de qui que ce soit ni de prétendre détenir toutes les réponses.</p>
            <p class="prose-body" style="margin-top:14px;max-width:none;">Je souhaite simplement partager ce que mon propre chemin m'a permis d'explorer, tout en laissant à chacun la liberté de ressentir, de questionner et de trouver ses propres réponses.</p>
            <p class="prose-body" style="margin-top:20px;max-width:none;font-style:italic;"><strong>Parce qu'au fond, le véritable chemin n'est pas de devenir quelqu'un d'autre.</strong><br><strong>C'est de revenir progressivement vers soi.</strong></p>`,

  // --- Page Parcours/Valeurs : section « Mes valeurs » ---
  about_values_eyebrow: '✦ Mes valeurs',
  about_values_title: 'Ce qui guide ma façon d\'accompagner',
  about_values_desc: "Pour moi, l'accompagnement commence avant toute guidance. Il repose d'abord sur la qualité de la présence, de l'écoute et de l'espace que nous créons ensemble.",
  about_values_cards: `<div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Bienveillance</span><h3>La douceur comme point de départ</h3><p>Une présence humaine, chaleureuse et sans jugement, où chacun peut avancer à son propre rythme.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Écoute</span><h3>Entendre au-delà des mots</h3><p>Une écoute attentive, profonde et sincère, permettant à chacun de se sentir réellement entendu.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Accueil</span><h3>Un espace où tu peux simplement être</h3><p>Un espace accueillant où tu peux te présenter tel que tu es, sans avoir à jouer un rôle.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Respect</span><h3>Honorer ton chemin</h3><p>Respecter ton rythme, tes choix, tes expériences, tes limites et ton parcours.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Honnêteté</span><h3>La vérité sans détour</h3><p>Une approche sincère, authentique et directe, toujours exprimée avec humanité et respect.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Transparence</span><h3>Rien à cacher, tout à clarifier</h3><p>Une communication claire sur l'accompagnement, ses intentions, son fonctionnement et ses limites.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Humilité</span><h3>Accompagner sans se placer au-dessus</h3><p>L'accompagnement n'est pas une position de supériorité. Chaque personne possède son propre chemin, son vécu et ses propres réponses.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Ouverture d'esprit</span><h3>Voir plus loin que les évidences</h3><p>Rester ouvert aux différentes perspectives, explorer et questionner sans imposer une vérité unique.</p></div>
          <div class="glass-card value-card"><div class="value-icon">✦</div><span class="value-label">Protection</span><h3>Un espace où l'intégrité est essentielle</h3><p>Créer un cadre respectueux, conscient et sécurisant, où l'intégrité et les limites de chacun sont essentielles.</p></div>`,

  // --- Page Services : section "Accompagnements personnalisés" ---
  services_accomp_eyebrow: 'Accompagnements personnalisés',
  services_accomp_title: "Un chemin d'accompagnement dans la durée",
  services_accomp_desc: "Au-delà des séances ponctuelles, ces parcours offrent un espace de continuité pour observer votre cheminement, intégrer vos prises de conscience et avancer avec davantage de clarté, à votre propre rythme.",

  // --- Page Services : section "Accompagnement Parent & Enfant" (avertissement) ---
  services_parent_title: 'Accompagnement Parent &amp; Enfant — à propos',
  services_parent_principle: "« Observer avant d'interpréter. Écouter avant de réagir. Comprendre avant d'intervenir. »",
  services_parent_text: "L'objectif n'est pas de changer ou catégoriser l'enfant, mais d'aider le parent à changer son regard et à développer une relation basée sur la présence, l'écoute, le respect et la compréhension.",
  services_parent_disclaimer: "Cet accompagnement est une démarche de réflexion, d'écoute et de développement personnel. Il ne remplace pas un médecin, un psychologue ou un professionnel de la santé. L'enfant n'est ni diagnostiqué, ni catégorisé, ni évalué médicalement, et doit toujours être respecté dans son individualité, son développement, son rythme et ses limites.",

  // --- Page Politique de confidentialité ---
  // Conforme à la Loi 25 (Québec) et à la LPRPDE/PIPEDA (Canada). Chaque
  // section est éditable depuis le panneau admin ; la date de dernière mise
  // à jour (privacy_policy_version, gérée séparément) se met à jour
  // automatiquement dès qu'une de ces sections est modifiée.
  privacy_hero_title: 'Politique de confidentialité',
  privacy_hero_subtitle: 'Conforme à la Loi 25 (Québec) et à la Loi sur la protection des renseignements personnels et les documents électroniques (LPRPDE/PIPEDA).',

  privacy_s1_title: '1. Responsable de la protection des renseignements personnels',
  privacy_s1_body: "<p style=\"margin-bottom:0;\">Pierre-Olivier Doucet agit à titre de responsable de la protection des renseignements personnels pour ce site. Pour toute question, demande d'accès, de correction ou de retrait de vos renseignements, vous pouvez le contacter à : <a href=\"mailto:confidentialite@3pierre6olivier9.com\" style=\"color:var(--gold-600,#A87C2E);\">confidentialite@3pierre6olivier9.com</a>.</p>",

  privacy_s2_title: '2. Renseignements collectés',
  privacy_s2_body: `<p style="margin-bottom:8px;">Lors de la création d'un compte ou d'une réservation, nous collectons :</p>
    <ul style="margin:0 0 0 20px;">
      <li>Nom et prénom</li>
      <li>Adresse courriel</li>
      <li>Date de naissance (uniquement pour valider l'âge minimum requis de 18 ans)</li>
      <li>Ville de résidence</li>
      <li>Historique de vos réservations et des services choisis</li>
      <li>Messages échangés avec Pierre-Olivier Doucet via le site</li>
      <li>Mot de passe (toujours conservé sous forme chiffrée, jamais en texte brut)</li>
      <li>Témoins de connexion essentiels (voir la section 11)</li>
    </ul>
    <p style="margin:12px 0 0;">Nous ne demandons jamais de renseignements sensibles (état de santé, origine, opinions ou autres renseignements de nature délicate). Si vous choisissez volontairement de nous en communiquer dans un message, ils sont protégés au même titre que vos autres renseignements personnels, leur accès est restreint, et ils ne sont jamais utilisés à d'autres fins que celle pour laquelle vous nous les avez transmis.</p>`,

  privacy_s3_title: '3. Finalités de la collecte',
  privacy_s3_body: `<p style="margin-bottom:8px;">Vos renseignements sont utilisés uniquement pour :</p>
    <ul style="margin:0 0 0 20px;">
      <li>Créer et gérer votre compte client</li>
      <li>Traiter vos réservations, en assurer le suivi et vous envoyer les confirmations correspondantes</li>
      <li>Vous contacter au sujet d'un rendez-vous (rappel, changement, annulation)</li>
      <li>Vérifier votre identité et votre âge</li>
      <li>Répondre aux messages que vous nous envoyez</li>
      <li>Assurer la sécurité et le bon fonctionnement du site</li>
      <li>Respecter nos obligations légales</li>
    </ul>
    <p style="margin:12px 0 0;">Nous ne vendons ni ne louons vos renseignements personnels à qui que ce soit, et nous ne les utilisons jamais à une fin non prévue ci-dessus sans votre consentement.</p>`,

  privacy_s4_title: '4. Consentement',
  privacy_s4_body: "<p style=\"margin-bottom:12px;\">La création d'un compte requiert votre consentement libre, éclairé et donné pour des fins précises — c'est pourquoi vous devez cocher la case de consentement avant de vous inscrire. Vous pouvez retirer ce consentement en tout temps en écrivant à <a href=\"mailto:confidentialite@3pierre6olivier9.com\" style=\"color:var(--gold-600,#A87C2E);\">confidentialite@3pierre6olivier9.com</a>.</p><p style=\"margin-bottom:0;\">Si le retrait de votre consentement rend impossible la poursuite de certains services (par exemple, la gestion de vos réservations), nous vous expliquerons clairement les conséquences avant de procéder.</p>",

  privacy_s5_title: '5. Conservation des renseignements',
  privacy_s5_body: "<p style=\"margin-bottom:0;\">Vos renseignements sont conservés seulement le temps nécessaire aux fins pour lesquelles ils ont été recueillis. Si vous demandez la suppression de votre compte, vos renseignements personnels identifiables sont supprimés ou anonymisés dans un délai raisonnable, sauf si une obligation légale exige leur conservation plus longtemps (par exemple, des motifs comptables ou fiscaux pour l'historique de réservations).</p>",

  privacy_s6_title: '6. Fournisseurs de services et hébergement',
  privacy_s6_body: `<p style="margin-bottom:12px;">Vos renseignements ne sont partagés qu'avec les fournisseurs strictement nécessaires au fonctionnement du site, notamment l'hébergement infonuagique (Render Services, Inc.) et l'envoi de courriels transactionnels. Ces fournisseurs sont contractuellement tenus d'assurer la confidentialité et la sécurité des renseignements auxquels ils ont accès, et ne peuvent les utiliser à aucune autre fin.</p>
    <p style="margin-bottom:0;">Comme notre hébergeur peut faire transiter ou stocker des données à l'extérieur du Québec, notamment aux États-Unis, nous nous assurons que le niveau de protection offert demeure équivalent à celui exigé par la loi québécoise. Vous pouvez demander des détails sur ce transfert en tout temps à <a href="mailto:confidentialite@3pierre6olivier9.com" style="color:var(--gold-600,#A87C2E);">confidentialite@3pierre6olivier9.com</a>.</p>`,

  privacy_s7_title: '7. Mesures de sécurité',
  privacy_s7_body: `<p style="margin-bottom:8px;">Nous appliquons des mesures de sécurité raisonnables pour protéger vos renseignements, notamment :</p>
    <ul style="margin:0 0 0 20px;">
      <li>Chiffrement des communications entre votre navigateur et nos serveurs (HTTPS/TLS)</li>
      <li>Chiffrement des mots de passe (technique de hachage sécurisée, jamais stockés en clair)</li>
      <li>Accès restreint aux renseignements personnels, limité aux personnes autorisées en ayant besoin pour l'exploitation du site</li>
      <li>Mesures de sécurité appliquées par notre hébergeur infonuagique</li>
    </ul>`,

  privacy_s8_title: '8. En cas d\'incident de confidentialité',
  privacy_s8_body: "<p style=\"margin-bottom:0;\">Si un incident portant atteinte à la confidentialité de vos renseignements personnels survenait et présentait un risque sérieux de préjudice, nous prendrions les mesures nécessaires pour en réduire les conséquences, documenterions l'incident dans un registre, et en aviserions la Commission d'accès à l'information du Québec (CAI) ainsi que le Commissariat à la protection de la vie privée du Canada (CPVP), lorsque requis par la loi. Les personnes concernées seraient également avisées lorsque la loi l'exige.</p>",

  privacy_s9_title: '9. Vos droits',
  privacy_s9_body: `<p style="margin-bottom:8px;">Conformément à la Loi 25 et à la LPRPDE, vous avez le droit de :</p>
    <ul style="margin:0 0 12px 20px;">
      <li>Accéder aux renseignements personnels que nous détenons à votre sujet</li>
      <li>Faire corriger des renseignements inexacts ou incomplets</li>
      <li>Retirer votre consentement à la collecte de vos renseignements, en tout temps</li>
      <li>Demander la suppression de votre compte et des renseignements associés</li>
      <li>Obtenir, lorsque applicable, une copie de vos renseignements dans un format structuré</li>
      <li>Porter plainte auprès de la Commission d'accès à l'information du Québec (CAI) ou du Commissariat à la protection de la vie privée du Canada (CPVP)</li>
    </ul>
    <p style="margin-bottom:12px;">Pour exercer l'un de ces droits, écrivez à <a href="mailto:confidentialite@3pierre6olivier9.com" style="color:var(--gold-600,#A87C2E);">confidentialite@3pierre6olivier9.com</a>. Nous répondrons à votre demande dans les délais prévus par la loi.</p>
    <p style="margin-bottom:0;">Notre clientèle est principalement établie au Québec ; les visiteurs de l'Union européenne demeurent occasionnels et nos activités ne constituent pas un traitement régulier ou systématique de leurs renseignements. Si le Règlement général sur la protection des données (RGPD) s'applique néanmoins à votre situation, vous disposez également des droits de rectification, d'effacement, de limitation, d'opposition et de portabilité, et pouvez vous adresser à la CNIL ou à l'autorité compétente de votre pays.</p>`,

  privacy_s10_title: '10. Âge minimum requis',
  privacy_s10_body: "<p style=\"margin-bottom:0;\">Ce site s'adresse uniquement aux personnes âgées de 18 ans ou plus. Votre date de naissance nous sert exclusivement à valider cet âge minimum lors de la création de votre compte ; toute tentative d'inscription indiquant un âge inférieur est automatiquement refusée. Nous ne cherchons jamais à recueillir sciemment des renseignements sur des personnes mineures.</p>",

  privacy_s11_title: '11. Témoins de connexion (cookies)',
  privacy_s11_body: "<p style=\"margin-bottom:12px;\">Le site utilise actuellement uniquement des témoins de connexion essentiels au fonctionnement du service, notamment pour maintenir votre session de connexion. Ces témoins ne peuvent être désactivés sans affecter le fonctionnement du site.</p><p style=\"margin-bottom:0;\">Si des outils de mesure d'audience ou de publicité (par exemple Facebook Pixel ou Google Analytics/Ads) étaient ajoutés au site, aucun témoin non essentiel ne serait activé avant l'obtention de votre consentement. Un bandeau vous permettrait alors d'accepter ou de refuser ces témoins, de retirer votre consentement en tout temps, et cette politique serait mise à jour pour identifier précisément les outils utilisés, les renseignements recueillis et leurs finalités.</p>",

  privacy_s12_title: '12. Modifications de cette politique',
  privacy_s12_body: "<p style=\"margin-bottom:0;\">Cette politique peut être mise à jour de temps à autre. La date de dernière mise à jour est indiquée en haut de cette page et se met à jour automatiquement chaque fois qu'une section est modifiée. En cas de changement important, vous en serez avisée lors de votre prochaine connexion ou par un avis affiché sur le site.</p>",
};

function ensureSiteContentSeed() {
  const insert = db.prepare(`INSERT OR IGNORE INTO site_content (key, value) VALUES (?, ?)`);
  const tx = db.transaction((entries) => {
    for (const [key, value] of entries) insert.run(key, value);
  });
  tx(Object.entries(SITE_CONTENT_DEFAULTS));
}
ensureSiteContentSeed();

// ---------- Migration unique : retrait "guidance intuitive" / "soins énergétiques" ----------
// Le site a évolué vers une identité centrée sur l'écoute et l'accompagnement humain.
// Cette migration ne s'exécute qu'une seule fois (marqueur en base) afin de :
//   1) désactiver les anciens services ponctuels de guidance/soins déjà enregistrés,
//   2) remettre à jour les textes de la page d'accueil qui en parlaient,
// sans jamais écraser une modification que Pierre-Olivier aurait faite depuis dans l'admin
// sur les autres champs.
function ensureGuidanceSoinsRemovalMigration() {
  const already = db.prepare('SELECT value FROM site_content WHERE key = ?').get('_migration_remove_guidance_soins_v1');
  if (already) return;

  const OLD_SERVICE_NAMES = [
    'Guidance Express',
    'Guidance Intuitive Personnalisée',
    'Petit Soin Énergétique',
    'Soin Énergétique Complet',
  ];
  const deactivate = db.prepare('UPDATE services SET active = 0 WHERE name = ?');
  OLD_SERVICE_NAMES.forEach((name) => deactivate.run(name));

  // "Rencontre Approfondie" existait déjà mais avec une description liée à la
  // guidance/aux soins énergétiques : on la met à jour plutôt que de la désactiver.
  db.prepare('UPDATE services SET description = ? WHERE name = ? AND description LIKE ?').run(
    'Un espace plus long pour explorer en profondeur une situation, un questionnement ou une période de transition.',
    'Rencontre Approfondie',
    '%énergétique%'
  );

  const upsertContent = db.prepare(`
    INSERT INTO site_content (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);
  const staleContentOverrides = {
    home_eyebrow: SITE_CONTENT_DEFAULTS.home_eyebrow,
    home_tagline: SITE_CONTENT_DEFAULTS.home_tagline,
    home_desc: SITE_CONTENT_DEFAULTS.home_desc,
    home_approach_title: SITE_CONTENT_DEFAULTS.home_approach_title,
    home_approach_p1: SITE_CONTENT_DEFAULTS.home_approach_p1,
  };
  for (const [key, value] of Object.entries(staleContentOverrides)) {
    upsertContent.run(key, value);
  }

  // Retrait des anciennes clés "services_soins_*", devenues obsolètes.
  db.prepare(`DELETE FROM site_content WHERE key LIKE 'services_soins_%'`).run();

  db.prepare('INSERT OR IGNORE INTO site_content (key, value) VALUES (?, ?)').run(
    '_migration_remove_guidance_soins_v1',
    new Date().toISOString()
  );
  console.log('✦ Migration effectuée : retrait des références à la guidance intuitive et aux soins énergétiques.');
}
ensureGuidanceSoinsRemovalMigration();

function getSiteContent() {
  const rows = db.prepare('SELECT key, value FROM site_content').all();
  const content = { ...SITE_CONTENT_DEFAULTS };
  for (const row of rows) content[row.key] = row.value;
  return content;
}

function formatPriceLabel(cents) {
  return (cents / 100).toFixed(2).replace('.', ',') + ' $';
}

// Retire les champs sensibles liés au jeton Accepter/Refuser avant d'envoyer
// une réservation au client (peu importe cliente ou admin) : le hash du
// jeton ne doit jamais quitter le serveur, même sous forme de hash.
function publicBooking(row) {
  const { accept_token_hash, accept_token_expires_at, previous_status, ...rest } = row;
  return { ...rest, awaitingResponse: !!accept_token_hash };
}

function publicService(row) {
  return {
    id: row.id,
    name: row.name,
    duration: row.duration,
    description: row.description,
    priceCents: row.price_cents,
    price: formatPriceLabel(row.price_cents),
    active: !!row.active,
    isProgram: !!row.is_program,
    programSessions: row.program_sessions || null,
  };
}

// ---------- Parcours multi-séances : progression toujours calculée en direct ----------
// Principe : la table "programs" ne stocke JAMAIS de compteurs (complétées, à venir,
// etc.) — uniquement le nombre total de séances prévu et le statut. Le détail de la
// progression est recalculé à chaque appel à partir des réservations (table
// "bookings") réellement liées à ce parcours, pour qu'il n'y ait jamais de
// désynchronisation possible entre l'affichage et l'état réel des rendez-vous.
function getProgramProgress(programId) {
  const program = db.prepare('SELECT * FROM programs WHERE id = ?').get(programId);
  if (!program) return null;

  const linkedBookings = db.prepare(`
    SELECT id, status, booking_date, booking_time, booking_date_label, program_seq
    FROM bookings WHERE program_id = ?
    ORDER BY program_seq ASC, booking_date ASC, booking_time ASC
  `).all(programId);

  const today = new Date().toISOString().slice(0, 10);
  let completed = 0, upcoming = 0, cancelled = 0;
  for (const b of linkedBookings) {
    if (b.status === 'annule') { cancelled++; continue; }
    if (b.booking_date < today) completed++; else upcoming++;
  }
  const scheduled = completed + upcoming;

  return {
    ...program,
    appointments: linkedBookings,
    completed_appointments: completed,
    upcoming_appointments: upcoming,
    cancelled_appointments: cancelled,
    scheduled_appointments: scheduled,
    remaining_to_schedule: Math.max(0, program.total_appointments - scheduled),
  };
}

// Recalcule et met à jour le statut d'un parcours ('actif' <-> 'termine') en
// fonction de sa progression réelle. Ne touche jamais un parcours 'annule'
// (annulation manuelle par l'admin, ne doit pas être ressuscitée automatiquement).
function refreshProgramStatus(programId) {
  if (!programId) return null;
  const progress = getProgramProgress(programId);
  if (!progress) return null;
  if (progress.program_status === 'annule') return progress;

  const today = new Date().toISOString().slice(0, 10);
  if (progress.completed_appointments >= progress.total_appointments && progress.program_status !== 'termine') {
    db.prepare(`UPDATE programs SET program_status = 'termine', end_date = ?, updated_at = datetime('now') WHERE id = ?`).run(today, programId);
    return getProgramProgress(programId);
  }
  if (progress.completed_appointments < progress.total_appointments && progress.program_status === 'termine') {
    // Ex : l'admin a rouvert / redaté une séance qui était comptée comme complétée.
    db.prepare(`UPDATE programs SET program_status = 'actif', end_date = NULL, updated_at = datetime('now') WHERE id = ?`).run(programId);
    return getProgramProgress(programId);
  }
  return progress;
}

// Trouve le parcours actif du client pour ce service (s'il reste de la place
// pour au moins une séance de plus), ou en crée un nouveau. Retourne l'id du
// parcours ainsi que le numéro de séance (program_seq) à attribuer à la
// nouvelle réservation.
function assignProgramForBooking(userId, service) {
  if (!service.isProgram) return { programId: null, programSeq: null };

  const active = db.prepare(`
    SELECT id FROM programs WHERE user_id = ? AND service_id = ? AND program_status = 'actif'
    ORDER BY id DESC LIMIT 1
  `).get(userId, service.id);

  let programId = active ? active.id : null;
  if (programId) {
    const progress = getProgramProgress(programId);
    if (!progress || progress.remaining_to_schedule <= 0) programId = null; // complet : nouveau parcours
  }

  if (!programId) {
    const ins = db.prepare(`
      INSERT INTO programs (user_id, service_id, service_name, total_appointments, program_status, start_date)
      VALUES (?, ?, ?, ?, 'actif', date('now'))
    `).run(userId, service.id, service.name, service.programSessions);
    programId = ins.lastInsertRowid;
  }

  const seqRow = db.prepare('SELECT COALESCE(MAX(program_seq), 0) as maxSeq FROM bookings WHERE program_id = ?').get(programId);
  return { programId, programSeq: seqRow.maxSeq + 1 };
}

// ---------- Rendez-vous proposés : jetons Accepter/Refuser sécurisés ----------
// Un rendez-vous "propose" (créé par l'admin pour la cliente, ou reporté par
// l'admin) doit être accepté ou refusé par la cliente via un lien reçu par
// courriel, sans avoir besoin de se connecter. Comme pour les jetons de
// réinitialisation de mot de passe, seule l'empreinte SHA-256 du jeton est
// stockée en base — jamais le jeton en clair — et chaque jeton n'est valide
// qu'une seule fois pour un seul rendez-vous précis.
const ACCEPT_TOKEN_VALIDITY_DAYS = 14;

function generateAcceptToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + ACCEPT_TOKEN_VALIDITY_DAYS * 24 * 60 * 60 * 1000).toISOString();
  return { token, hash, expiresAt };
}

// Retrouve un rendez-vous par jeton (jamais par id dans l'URL, pour ne
// jamais exposer ou permettre de deviner l'accès aux rendez-vous d'une
// autre cliente). Retourne null si le jeton est invalide, expiré, ou si la
// cliente a déjà répondu (usage unique).
function findPendingBookingByToken(token) {
  if (!token || typeof token !== 'string') return null;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const record = db.prepare(`
    SELECT bookings.*, users.name as client_name, users.email as client_email
    FROM bookings JOIN users ON users.id = bookings.user_id
    WHERE bookings.accept_token_hash = ?
  `).get(hash);
  if (!record) return null;
  if (record.responded_at) return null;
  if (record.accept_token_expires_at && record.accept_token_expires_at < new Date().toISOString()) return null;
  return record;
}

function getActiveServices() {
  return db.prepare('SELECT * FROM services WHERE active = 1 ORDER BY sort_order ASC, id ASC').all();
}

function getServiceById(id) {
  return db.prepare('SELECT * FROM services WHERE id = ?').get(id);
}

// Nombre maximum de services actifs que Pierre-Olivier peut avoir en même temps
// dans son catalogue (affichés sur le site et proposés à la réservation).
const MAX_ACTIVE_SERVICES = 10;

// Date de dernière mise à jour de la politique de confidentialité, stockée
// en base (site_content, clé "privacy_policy_version") plutôt que codée en
// dur : elle se met à jour automatiquement dès qu'une section de la
// politique est modifiée depuis le panneau admin (voir
// bumpPrivacyPolicyVersionIfNeeded). Les consentements déjà enregistrés
// gardent la version qui était en vigueur au moment de l'inscription, pour
// garder une preuve fidèle de ce à quoi la cliente a réellement consenti.
const DEFAULT_PRIVACY_POLICY_VERSION = '2026-09-04';

function getPrivacyPolicyVersion() {
  const row = db.prepare("SELECT value FROM site_content WHERE key = 'privacy_policy_version'").get();
  return row ? row.value : DEFAULT_PRIVACY_POLICY_VERSION;
}

function bumpPrivacyPolicyVersionIfNeeded(updatedKeys) {
  if (!updatedKeys.some((k) => k.startsWith('privacy_'))) return;
  const today = new Date().toISOString().slice(0, 10);
  db.prepare(`
    INSERT INTO site_content (key, value, updated_at) VALUES ('privacy_policy_version', ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
  `).run(today);
}

// ---------- Création automatique du compte admin (Pierre-Olivier) au démarrage ----------
function ensureAdminAccount() {
  const adminEmail = (process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com').toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
  if (existing) return;

  const password = process.env.ADMIN_PASSWORD || 'changez-moi-123';
  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')`)
    .run('Pierre-Olivier Doucet', adminEmail, hash);
  console.log(`✦ Compte admin créé : ${adminEmail} (mot de passe défini dans .env -> ADMIN_PASSWORD)`);
}
ensureAdminAccount();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieSession({
  name: 'pierreolivierdoucet_session',
  keys: [process.env.SESSION_SECRET || 'dev-secret-changez-moi'],
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 jours
}));
app.use(express.static(path.join(__dirname, 'public')));

// Route publique dédiée : permet de partager/mettre en signet un lien direct
// vers la politique de confidentialité, sans connexion requise. Le site est
// une page unique (SPA) sans routage d'URL — cette route sert donc le même
// index.html, et un petit script au chargement (voir index.html) détecte ce
// chemin pour afficher directement la bonne page plutôt que l'accueil.
app.get('/politique-confidentialite', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// Middlewares d'authentification
// ============================================================
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Vous devez être connecté.' });
  // Maintient last_activity_at à jour pendant toute la durée d'une session
  // active, pas seulement au moment de la connexion (une session dure
  // jusqu'à 30 jours). Non-bloquant : une erreur ici ne doit jamais empêcher
  // la requête en cours de continuer.
  try {
    db.prepare(`UPDATE users SET last_activity_at = datetime('now'), inactivity_warning_sent_at = NULL WHERE id = ?`)
      .run(req.session.userId);
  } catch (e) { /* silencieux */ }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId || req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Accès réservé à l\'administration.' });
  }
  next();
}

// Règle de robustesse du mot de passe, appliquée partout où un mot de passe
// est créé ou modifié (inscription, réinitialisation, changement de mot de
// passe client ou admin) : au moins 8 caractères, une majuscule et un
// caractère spécial. Retourne null si valide, ou un message d'erreur en
// français destiné à être renvoyé directement au frontend.
function validatePasswordStrength(password) {
  if (typeof password !== 'string' || password.length < 8) {
    return 'Le mot de passe doit contenir au moins 8 caractères.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Le mot de passe doit contenir au moins une lettre majuscule.';
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'Le mot de passe doit contenir au moins un caractère spécial.';
  }
  return null;
}

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, role: row.role };
}

// ============================================================
// AUTHENTIFICATION
// ============================================================

// Inscription cliente
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, birthDate, city, consentAccepted } = req.body;
    if (!name || !email || !password || !birthDate || !city) return res.status(400).json({ error: 'Champs manquants.' });
    const passwordError = validatePasswordStrength(password);
    if (passwordError) return res.status(400).json({ error: passwordError });
    // Le consentement à la collecte de renseignements personnels (Loi 25 /
    // PIPEDA) est obligatoire. Le frontend ne permet normalement pas
    // d'arriver ici sans avoir cliqué « J'accepte » dans la fenêtre de
    // consentement, mais on revalide côté serveur par sécurité.
    if (consentAccepted !== true) {
      return res.status(400).json({ error: 'Vous devez accepter la politique de confidentialité pour créer un compte.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Vérification de la liste noire : un email bloqué reste bloqué définitivement,
    // même si une date de naissance valide est fournie lors d'une nouvelle tentative.
    const blocked = db.prepare('SELECT id FROM blocked_emails WHERE email = ?').get(normalizedEmail);
    if (blocked) {
      return res.status(403).json({ error: 'Cette adresse courriel ne peut pas créer de compte.' });
    }

    // Validation de la date de naissance et de l'âge minimum (18 ans)
    const birth = new Date(birthDate);
    if (Number.isNaN(birth.getTime())) {
      return res.status(400).json({ error: 'Date de naissance invalide.' });
    }
    const today = new Date();
    if (birth > today) {
      return res.status(400).json({ error: 'Date de naissance invalide.' });
    }
    let age = today.getFullYear() - birth.getFullYear();
    const hasNotHadBirthdayThisYear =
      today.getMonth() < birth.getMonth() ||
      (today.getMonth() === birth.getMonth() && today.getDate() < birth.getDate());
    if (hasNotHadBirthdayThisYear) age--;

    if (age < 18) {
      // L'email est bloqué définitivement et Pierre-Olivier est avertie par courriel.
      try {
        db.prepare('INSERT OR IGNORE INTO blocked_emails (email, reason) VALUES (?, ?)')
          .run(normalizedEmail, 'age_minimum_non_respecte');
      } catch (blockErr) {
        console.error('Erreur lors du blocage de l\'email :', blockErr.message);
      }
      try {
        await sendUnderageAttemptAlert({ email: normalizedEmail, name: name.trim(), birthDate });
      } catch (mailErr) {
        console.error('Erreur lors de l\'envoi de l\'alerte âge minimum :', mailErr.message);
      }
      return res.status(403).json({ error: 'Vous devez avoir au moins 18 ans pour créer un compte.' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
    if (existing) return res.status(409).json({ error: 'Un compte existe déjà avec ce courriel.' });

    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`INSERT INTO users (name, email, password_hash, birth_date, city, role) VALUES (?, ?, ?, ?, ?, 'client')`)
      .run(name.trim(), normalizedEmail, hash, birthDate, city.trim());

    const user = { id: result.lastInsertRowid, name: name.trim(), email: normalizedEmail, role: 'client' };
    req.session.userId = user.id;
    req.session.role = user.role;

    // Enregistrement du consentement (Loi 25 / PIPEDA) : horodatage, version
    // de la politique acceptée, et adresse IP, conservés indépendamment du
    // compte pour servir de preuve même si le compte est supprimé ensuite.
    try {
      const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
      db.prepare(`
        INSERT INTO consent_records (user_id, email, policy_version, ip_address)
        VALUES (?, ?, ?, ?)
      `).run(user.id, normalizedEmail, getPrivacyPolicyVersion(), clientIp || null);
    } catch (consentErr) {
      // Ne doit jamais empêcher la création du compte ; on logue pour pouvoir
      // vérifier manuellement si l'enregistrement du consentement a échoué.
      console.error('⚠️  Erreur enregistrement du consentement :', consentErr.message);
    }

    res.json({ user });
  } catch (err) {
    console.error('Erreur register :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de l\'inscription.' });
  }
});

// ============================================================
// Mot de passe oublié — demande de réinitialisation
// ============================================================
// Vérifie que l'email ET la date de naissance correspondent à un même compte
// (évite d'envoyer un lien suite à une simple faute de frappe sur un email
// qui appartiendrait à quelqu'un d'autre, et limite les doublons de demandes).
app.post('/api/auth/forgot-password', async (req, res) => {
  // Message volontairement identique dans tous les cas de "non trouvé", pour
  // ne jamais révéler si un email existe ou non dans la base.
  const genericResponse = {
    message: 'Si ces informations correspondent à un compte existant, un courriel contenant un lien de réinitialisation vient de vous être envoyé.',
  };
  try {
    const { email, birthDate } = req.body;
    if (!email || !birthDate) return res.status(400).json({ error: 'Champs manquants.' });

    const normalizedEmail = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND birth_date = ?').get(normalizedEmail, birthDate);

    if (!user) {
      // On répond comme si tout allait bien, sans dire si l'email existe ou si c'est la date qui ne correspond pas.
      return res.json(genericResponse);
    }

    // Invalide les anciens jetons non utilisés pour ce compte, pour éviter
    // d'accumuler des liens valides en doublon.
    db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0').run(user.id);

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // valide 1 heure

    db.prepare('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)')
      .run(user.id, tokenHash, expiresAt);

    try {
      await sendPasswordResetEmail({ name: user.name, email: user.email, rawToken });
    } catch (mailErr) {
      console.error('Erreur lors de l\'envoi du courriel de réinitialisation :', mailErr.message);
    }

    res.json(genericResponse);
  } catch (err) {
    console.error('Erreur forgot-password :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Confirmation de la réinitialisation : vérifie le jeton et met à jour le mot de passe
app.post('/api/auth/reset-password', (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: 'Champs manquants.' });
    const passwordError = validatePasswordStrength(newPassword);
    if (passwordError) return res.status(400).json({ error: passwordError });

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const resetRow = db.prepare('SELECT * FROM password_resets WHERE token_hash = ?').get(tokenHash);

    if (!resetRow || resetRow.used === 1) {
      return res.status(400).json({ error: 'Ce lien de réinitialisation est invalide ou a déjà été utilisé.' });
    }
    if (new Date(resetRow.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Ce lien de réinitialisation a expiré. Veuillez en demander un nouveau.' });
    }

    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, resetRow.user_id);
    db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?').run(resetRow.id);

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur reset-password :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Connexion
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Champs manquants.' });

    const normalizedEmail = email.trim().toLowerCase();
    const row = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);
    if (!row) return res.status(401).json({ error: 'Courriel ou mot de passe incorrect.' });

    const valid = bcrypt.compareSync(password, row.password_hash);
    if (!valid) return res.status(401).json({ error: 'Courriel ou mot de passe incorrect.' });

    // Une connexion réussie marque le compte comme actif : on annule tout
    // avertissement d'inactivité déjà envoyé pour la période précédente.
    db.prepare(`UPDATE users SET last_activity_at = datetime('now'), inactivity_warning_sent_at = NULL WHERE id = ?`)
      .run(row.id);

    req.session.userId = row.id;
    req.session.role = row.role;
    res.json({ user: publicUser(row) });
  } catch (err) {
    console.error('Erreur login :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la connexion.' });
  }
});

// Déconnexion
app.post('/api/auth/logout', (req, res) => {
  req.session = null;
  res.json({ success: true });
});

// Qui suis-je ?
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!row) return res.json({ user: null });
  res.json({ user: publicUser(row) });
});

// Changement de mot de passe par la personne elle-même (cliente ou admin),
// une fois connectée. Exige le mot de passe actuel pour confirmer
// l'identité, distinct du flux « mot de passe oublié » qui passe par un
// jeton envoyé par courriel.
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Champs manquants.' });

    const passwordError = validatePasswordStrength(newPassword);
    if (passwordError) return res.status(400).json({ error: passwordError });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Session invalide.' });

    const matches = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!matches) return res.status(400).json({ error: 'Le mot de passe actuel est incorrect.' });

    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur change-password :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ============================================================
// RÉSERVATIONS (côté cliente connectée)
// ============================================================

app.post('/api/bookings', requireAuth, async (req, res) => {
  try {
    const { serviceId, bookingDate, bookingDateLabel, bookingTime } = req.body;
    const serviceRow = getServiceById(serviceId);
    if (!serviceRow || !serviceRow.active) return res.status(400).json({ error: 'Service invalide.' });
    if (!bookingDate || !bookingTime) return res.status(400).json({ error: 'Date ou heure manquante.' });

    // Le prix et le nom du service sont figés au moment de la réservation :
    // toute modification ultérieure du catalogue par l'admin n'affecte pas
    // les réservations déjà enregistrées.
    const service = publicService(serviceRow);

    // Empêche deux clientes de réserver le même créneau
    const conflict = db.prepare(`
      SELECT id FROM bookings WHERE booking_date = ? AND booking_time = ? AND status != 'annule'
    `).get(bookingDate, bookingTime);
    if (conflict) return res.status(409).json({ error: 'Ce créneau vient d\'être réservé par quelqu\'un d\'autre. Choisissez-en un autre.' });

    // Seul le virement Interac est proposé : la réservation reste toujours
    // en attente jusqu'à confirmation manuelle de Pierre-Olivier dans l'espace admin,
    // une fois le virement reçu.
    const paymentMethod = 'interac';
    const status = 'en_attente';

    // Si ce service fait partie d'un parcours multi-séances (3 mois / 6 mois /
    // Parent & Enfant), on rattache automatiquement cette réservation au
    // parcours actif du client pour ce service (ou on en crée un nouveau).
    const { programId, programSeq } = assignProgramForBooking(req.session.userId, service);

    const result = db.prepare(`
      INSERT INTO bookings (user_id, service_name, service_price_cents, booking_date, booking_date_label, booking_time, payment_method, status, program_id, program_seq)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.session.userId, service.name, service.priceCents, bookingDate, bookingDateLabel || bookingDate, bookingTime, paymentMethod, status, programId, programSeq);

    if (programId) refreshProgramStatus(programId);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    try {
      await sendConfirmationEmails({
        clientName: user.name,
        clientEmail: user.email,
        service,
        bookingDateLabel: bookingDateLabel || bookingDate,
        bookingTime,
        paymentMethod,
        status,
      });
    } catch (emailErr) {
      console.error('⚠️  Erreur envoi email (réservation tout de même enregistrée) :', emailErr.message);
    }

    res.json({ success: true, bookingId: result.lastInsertRowid, status, programId, programSeq });
  } catch (err) {
    console.error('Erreur création réservation :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la réservation.' });
  }
});

// Liste des réservations de la cliente connectée, avec la progression du
// parcours (si applicable) intégrée directement à chaque réservation concernée.
app.get('/api/bookings/mine', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM bookings WHERE user_id = ? ORDER BY booking_date DESC, booking_time DESC')
    .all(req.session.userId);

  const programCache = new Map();
  const withProgress = rows.map((b) => {
    const clean = publicBooking(b);
    if (!b.program_id) return clean;
    if (!programCache.has(b.program_id)) programCache.set(b.program_id, getProgramProgress(b.program_id));
    const p = programCache.get(b.program_id);
    return {
      ...clean,
      program: p ? {
        id: p.id,
        totalAppointments: p.total_appointments,
        completedAppointments: p.completed_appointments,
        upcomingAppointments: p.upcoming_appointments,
        remainingToSchedule: p.remaining_to_schedule,
        status: p.program_status,
      } : null,
    };
  });
  res.json(withProgress);
});

// Liste des parcours multi-séances de la cliente connectée, avec progression.
app.get('/api/programs/mine', requireAuth, (req, res) => {
  const programs = db.prepare('SELECT id FROM programs WHERE user_id = ? ORDER BY created_at DESC').all(req.session.userId);
  res.json(programs.map((p) => getProgramProgress(p.id)));
});

// Annuler une réservation (seulement la sienne, et seulement si future)
app.post('/api/bookings/:id/cancel', requireAuth, (req, res) => {
  const booking = db.prepare('SELECT * FROM bookings WHERE id = ?').get(req.params.id);
  if (!booking) return res.status(404).json({ error: 'Réservation introuvable.' });
  if (booking.user_id !== req.session.userId) return res.status(403).json({ error: 'Cette réservation ne vous appartient pas.' });

  db.prepare(`UPDATE bookings SET status = 'annule' WHERE id = ?`).run(req.params.id);
  if (booking.program_id) refreshProgramStatus(booking.program_id);
  res.json({ success: true });
});

// Suppression volontaire du compte par la cliente elle-même (Loi 25 / PIPEDA).
// Irréversible : supprime le compte ainsi que toutes les données qui s'y
// rattachent (réservations, conversation, témoignages). Réservée aux
// comptes "client" : un compte admin ne peut pas se supprimer par cette voie.
app.post('/api/account/delete', requireAuth, (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    if (!user) return res.status(404).json({ error: 'Compte introuvable.' });
    if (user.role !== 'client') {
      return res.status(403).json({ error: 'Cette action n\'est pas disponible pour ce type de compte.' });
    }

    deleteClientAccount(user.id);
    logRetentionEvent('account_self_deleted', `Compte client #${user.id} supprimé volontairement par la cliente.`);
    req.session = null; // termine la session active immédiatement
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur suppression volontaire du compte :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la suppression du compte.' });
  }
});

// ============================================================
// DISPONIBILITÉS (heures d'ouverture + blocages admin + réservations)
// ============================================================

// Convertit "HH:MM" en minutes depuis minuit, pour comparer facilement des plages.
function timeToMinutes(hhmm) {
  const [h, m] = hhmm.split(':').map(Number);
  return h * 60 + m;
}
function minutesToTime(mins) {
  const h = Math.floor(mins / 60).toString().padStart(2, '0');
  const m = (mins % 60).toString().padStart(2, '0');
  return `${h}:${m}`;
}

function getBusinessHoursForWeekday(weekday) {
  return db.prepare('SELECT * FROM business_hours WHERE weekday = ?').get(weekday);
}

function getBlockedPeriodsForDate(dateStr) {
  return db.prepare('SELECT * FROM blocked_periods WHERE blocked_date = ?').all(dateStr);
}

// Calcule la liste des créneaux disponibles pour une date donnée (AAAA-MM-JJ),
// en combinant : heures d'ouverture par défaut du jour de la semaine,
// blocages ponctuels créés par Pierre-Olivier (jour complet ou plage précise),
// et réservations déjà existantes (statut différent de "annulé").
function computeAvailableSlots(dateStr) {
  const date = new Date(dateStr + 'T00:00:00');
  if (Number.isNaN(date.getTime())) return [];
  const weekday = date.getDay();

  const hours = getBusinessHoursForWeekday(weekday);
  if (!hours || !hours.is_open) return [];

  const blocks = getBlockedPeriodsForDate(dateStr);
  // Un blocage sans heure de début/fin = jour complet fermé.
  if (blocks.some(b => !b.start_time || !b.end_time)) return [];

  const taken = db.prepare(`
    SELECT booking_time FROM bookings WHERE booking_date = ? AND status != 'annule'
  `).all(dateStr).map(r => r.booking_time);

  const duration = hours.slot_duration_minutes || 30;
  const gap = hours.break_between_slots_minutes || 0;
  const step = duration + gap; // espacement fixe entre le début de chaque créneau
  const slots = [];
  for (let t = timeToMinutes(hours.start_time); t + duration <= timeToMinutes(hours.end_time); t += step) {
    const slotLabel = minutesToTime(t);
    const slotEnd = t + duration;

    // Exclu si dans la pause déjeuner habituelle (s'il y en a une).
    if (hours.break_start && hours.break_end) {
      const breakStart = timeToMinutes(hours.break_start);
      const breakEnd = timeToMinutes(hours.break_end);
      if (t < breakEnd && slotEnd > breakStart) continue;
    }

    // Exclu si dans une plage bloquée ponctuelle.
    const isBlocked = blocks.some(b => {
      const bStart = timeToMinutes(b.start_time);
      const bEnd = timeToMinutes(b.end_time);
      return t < bEnd && slotEnd > bStart;
    });
    if (isBlocked) continue;

    // Exclu si déjà réservé.
    if (taken.includes(slotLabel)) continue;

    slots.push(slotLabel);
  }
  return slots;
}

// Route publique (lecture seule) : permet au calendrier client de savoir
// quels jours de la semaine sont ouverts, pour griser les jours fermés
// sans avoir à interroger /api/availability pour chaque jour affiché.
app.get('/api/business-hours', (req, res) => {
  const rows = db.prepare('SELECT * FROM business_hours ORDER BY weekday ASC').all();
  res.json(rows.map(r => ({
    weekday: r.weekday,
    isOpen: !!r.is_open,
    startTime: r.start_time,
    endTime: r.end_time,
  })));
});

// Route publique : utilisée par l'étape "calendrier" de la réservation.
// Remplace l'ancienne génération de créneaux codée en dur côté client.
app.get('/api/availability', (req, res) => {
  const { date } = req.query;
  if (!date) return res.status(400).json({ error: 'Paramètre date manquant.' });
  res.json({ date, slots: computeAvailableSlots(date) });
});
// Conservée pour compatibilité : créneaux déjà pris pour une date donnée.
// La nouvelle route /api/availability est désormais la source recommandée
// côté client, car elle tient aussi compte des heures d'ouverture et des
// blocages admin, pas seulement des réservations existantes.
app.get('/api/bookings/taken', (req, res) => {
  const { date } = req.query; // format AAAA-MM-JJ
  if (!date) return res.status(400).json({ error: 'Paramètre date manquant.' });
  const rows = db.prepare(`SELECT booking_time FROM bookings WHERE booking_date = ? AND status != 'annule'`).all(date);
  res.json({ takenTimes: rows.map(r => r.booking_time) });
});

// ============================================================
// SERVICES (catalogue public — lu par le site pour afficher les services)
// ============================================================

app.get('/api/services', (req, res) => {
  const rows = getActiveServices();
  res.json(rows.map(publicService));
});

// ============================================================
// ESPACE ADMIN (Pierre-Olivier voit tout)
// ============================================================

app.get('/api/admin/bookings', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT bookings.*, users.name as client_name, users.email as client_email
    FROM bookings
    JOIN users ON users.id = bookings.user_id
    ORDER BY booking_date DESC, booking_time DESC
  `).all();

  const programCache = new Map();
  const withProgress = rows.map((b) => {
    const clean = publicBooking(b);
    if (!b.program_id) return clean;
    if (!programCache.has(b.program_id)) programCache.set(b.program_id, getProgramProgress(b.program_id));
    const p = programCache.get(b.program_id);
    return {
      ...clean,
      program: p ? {
        id: p.id,
        totalAppointments: p.total_appointments,
        completedAppointments: p.completed_appointments,
        upcomingAppointments: p.upcoming_appointments,
        remainingToSchedule: p.remaining_to_schedule,
        status: p.program_status,
      } : null,
    };
  });
  res.json(withProgress);
});

// Propose un nouveau rendez-vous au nom d'une cliente déjà inscrite (ex :
// réservation prise par téléphone). La cliente doit reçoit un courriel et
// doit Accepter/Refuser via un lien sécurisé avant que le rendez-vous ne
// devienne réel — il n'apparaît qu'en statut "propose" jusque-là, mais
// occupe déjà le créneau pour éviter un double-réservation.
app.post('/api/admin/bookings', requireAdmin, async (req, res) => {
  try {
    const { clientEmail, serviceId, bookingDate, bookingDateLabel, bookingTime, alreadyPaid } = req.body;
    if (!clientEmail || !serviceId || !bookingDate || !bookingTime) {
      return res.status(400).json({ error: 'Champs manquants.' });
    }

    const normalizedEmail = String(clientEmail).trim().toLowerCase();
    const client = db.prepare("SELECT * FROM users WHERE email = ? AND role = 'client'").get(normalizedEmail);
    if (!client) {
      return res.status(404).json({ error: 'Aucune cliente avec ce courriel. Elle doit d\'abord créer un compte sur le site.' });
    }

    const serviceRow = getServiceById(serviceId);
    if (!serviceRow || !serviceRow.active) return res.status(400).json({ error: 'Service invalide.' });
    const service = publicService(serviceRow);

    const conflict = db.prepare(`SELECT id FROM bookings WHERE booking_date = ? AND booking_time = ? AND status != 'annule'`).get(bookingDate, bookingTime);
    if (conflict) return res.status(409).json({ error: 'Ce créneau est déjà occupé.' });

    const { programId, programSeq } = assignProgramForBooking(client.id, service);
    const { token, hash, expiresAt } = generateAcceptToken();
    // previous_status = le statut à appliquer dès que la cliente accepte.
    const targetStatusOnAccept = alreadyPaid === true ? 'confirme' : 'en_attente';

    const result = db.prepare(`
      INSERT INTO bookings (user_id, service_name, service_price_cents, booking_date, booking_date_label, booking_time, payment_method, status, program_id, program_seq, accept_token_hash, accept_token_expires_at, previous_status)
      VALUES (?, ?, ?, ?, ?, ?, 'interac', 'propose', ?, ?, ?, ?, ?)
    `).run(client.id, service.name, service.priceCents, bookingDate, bookingDateLabel || bookingDate, bookingTime, programId, programSeq, hash, expiresAt, targetStatusOnAccept);

    if (programId) refreshProgramStatus(programId);

    try {
      await sendAppointmentProposalEmail({
        clientName: client.name,
        clientEmail: client.email,
        service,
        bookingDateLabel: bookingDateLabel || bookingDate,
        bookingTime,
        token,
        isReschedule: false,
      });
    } catch (emailErr) {
      console.error('⚠️  Erreur envoi courriel de proposition de rendez-vous :', emailErr.message);
    }

    res.json({ success: true, bookingId: result.lastInsertRowid });
  } catch (err) {
    console.error('Erreur création réservation (admin) :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Reporte (change la date/heure) d'un rendez-vous existant. La cliente doit
// Accepter/Refuser la nouvelle date via courriel avant que le changement ne
// soit définitif ; son statut d'origine (confirmé ou en attente de
// paiement) est conservé et réappliqué automatiquement si elle accepte.
app.post('/api/admin/bookings/:id/reschedule', requireAdmin, async (req, res) => {
  try {
    const { bookingDate, bookingDateLabel, bookingTime } = req.body;
    if (!bookingDate || !bookingTime) return res.status(400).json({ error: 'Date ou heure manquante.' });

    const booking = db.prepare(`
      SELECT bookings.*, users.name as client_name, users.email as client_email
      FROM bookings JOIN users ON users.id = bookings.user_id
      WHERE bookings.id = ?
    `).get(req.params.id);
    if (!booking) return res.status(404).json({ error: 'Réservation introuvable.' });
    if (booking.status === 'annule') return res.status(400).json({ error: 'Impossible de reporter une réservation annulée.' });

    const conflict = db.prepare(`SELECT id FROM bookings WHERE booking_date = ? AND booking_time = ? AND status != 'annule' AND id != ?`)
      .get(bookingDate, bookingTime, booking.id);
    if (conflict) return res.status(409).json({ error: 'Ce créneau est déjà occupé.' });

    // Ne pas écraser previous_status si le rendez-vous était déjà en attente
    // de réponse (sinon on perdrait son vrai statut d'origine).
    const statusToRestore = booking.status === 'propose' ? booking.previous_status : booking.status;
    const { token, hash, expiresAt } = generateAcceptToken();

    db.prepare(`
      UPDATE bookings SET booking_date = ?, booking_date_label = ?, booking_time = ?, status = 'propose',
        previous_status = ?, accept_token_hash = ?, accept_token_expires_at = ?, responded_at = NULL
      WHERE id = ?
    `).run(bookingDate, bookingDateLabel || bookingDate, bookingTime, statusToRestore, hash, expiresAt, booking.id);

    try {
      await sendAppointmentProposalEmail({
        clientName: booking.client_name,
        clientEmail: booking.client_email,
        service: { name: booking.service_name, price: formatPriceLabel(booking.service_price_cents) },
        bookingDateLabel: bookingDateLabel || bookingDate,
        bookingTime,
        token,
        isReschedule: true,
      });
    } catch (emailErr) {
      console.error('⚠️  Erreur envoi courriel de report de rendez-vous :', emailErr.message);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur report de réservation :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ---------- Parcours multi-séances (admin) ----------

app.get('/api/admin/programs', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT programs.id, users.name as client_name, users.email as client_email
    FROM programs JOIN users ON users.id = programs.user_id
    ORDER BY programs.created_at DESC
  `).all();
  res.json(rows.map((r) => ({ ...getProgramProgress(r.id), client_name: r.client_name, client_email: r.client_email })));
});

app.get('/api/admin/programs/:id', requireAdmin, (req, res) => {
  const owner = db.prepare(`
    SELECT programs.id, users.name as client_name, users.email as client_email
    FROM programs JOIN users ON users.id = programs.user_id
    WHERE programs.id = ?
  `).get(req.params.id);
  if (!owner) return res.status(404).json({ error: 'Parcours introuvable.' });
  res.json({ ...getProgramProgress(owner.id), client_name: owner.client_name, client_email: owner.client_email });
});

// Annulation d'un parcours par l'admin : arrête le suivi et annule toutes les
// séances futures (en_attente/confirmées) qui n'ont pas encore eu lieu. Les
// séances déjà passées restent inchangées dans l'historique du client.
app.post('/api/admin/programs/:id/cancel', requireAdmin, async (req, res) => {
  const progress = getProgramProgress(req.params.id);
  if (!progress) return res.status(404).json({ error: 'Parcours introuvable.' });

  const today = new Date().toISOString().slice(0, 10);
  const futureActive = progress.appointments.filter((b) => b.status !== 'annule' && b.booking_date >= today);

  db.prepare(`UPDATE programs SET program_status = 'annule', end_date = ?, updated_at = datetime('now') WHERE id = ?`)
    .run(today, req.params.id);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(progress.user_id);
  for (const b of futureActive) {
    db.prepare(`UPDATE bookings SET status = 'annule' WHERE id = ?`).run(b.id);
    const bookingFull = db.prepare('SELECT * FROM bookings WHERE id = ?').get(b.id);
    try {
      await sendConfirmationEmails({
        clientName: user.name,
        clientEmail: user.email,
        service: { name: progress.service_name, price: formatPriceLabel(bookingFull.service_price_cents) },
        bookingDateLabel: b.booking_date_label,
        bookingTime: b.booking_time,
        paymentMethod: bookingFull.payment_method,
        status: 'annule',
        notifyAdmin: false,
      });
    } catch (emailErr) {
      console.error('⚠️  Erreur envoi courriel (annulation de parcours) :', emailErr.message);
    }
  }

  res.json({ success: true, cancelledAppointments: futureActive.length });
});

app.get('/api/admin/clients', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, name, email, phone, created_at FROM users WHERE role = 'client' ORDER BY created_at DESC`).all();
  res.json(rows);
});

// Supprime définitivement tous les rendez-vous dont la date est déjà passée.
// Route déclarée AVANT /api/admin/bookings/:id/status pour éviter tout conflit de routage.
app.delete('/api/admin/bookings/history', requireAdmin, (req, res) => {
  const result = db.prepare(`
    DELETE FROM bookings WHERE booking_date < date('now')
  `).run();

  res.json({ success: true, deletedCount: result.changes });
});

app.post('/api/admin/bookings/:id/status', requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['en_attente', 'confirme', 'annule'].includes(status)) return res.status(400).json({ error: 'Statut invalide.' });

  // On récupère la réservation + les infos du client AVANT la mise à jour,
  // afin de pouvoir lui envoyer un courriel reflétant le nouveau statut.
  const booking = db.prepare(`
    SELECT bookings.*, users.name as client_name, users.email as client_email
    FROM bookings JOIN users ON users.id = bookings.user_id
    WHERE bookings.id = ?
  `).get(req.params.id);

  if (!booking) return res.status(404).json({ error: 'Réservation introuvable.' });

  db.prepare(`UPDATE bookings SET status = ?, accept_token_hash = NULL, accept_token_expires_at = NULL WHERE id = ?`).run(status, req.params.id);
  if (booking.program_id) refreshProgramStatus(booking.program_id);

  // Le courriel ne doit jamais empêcher la mise à jour du statut en cas d'échec d'envoi.
  try {
    await sendConfirmationEmails({
      clientName: booking.client_name,
      clientEmail: booking.client_email,
      service: { name: booking.service_name, price: formatPriceLabel(booking.service_price_cents) },
      bookingDateLabel: booking.booking_date_label,
      bookingTime: booking.booking_time,
      paymentMethod: booking.payment_method,
      status,
      notifyAdmin: false,
    });
  } catch (emailErr) {
    console.error('⚠️  Erreur envoi courriel de changement de statut :', emailErr.message);
  }

  res.json({ success: true });
});

// ---------- Gestion du catalogue des services (prix + description) ----------

// Liste complète (y compris services désactivés, s'il y en a) pour l'admin
app.get('/api/admin/services', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM services ORDER BY sort_order ASC, id ASC').all();
  res.json(rows.map(publicService));
});

// Mise à jour du prix et/ou de la description d'un service.
// Important : ceci ne modifie QUE le catalogue affiché pour les futures
// réservations. Les réservations déjà enregistrées gardent en mémoire le
// nom et le prix tels qu'ils étaient au moment de la réservation
// (colonnes service_name / service_price_cents de la table bookings),
// donc rien ne change rétroactivement pour les rendez-vous déjà pris.
app.put('/api/admin/services/:id', requireAdmin, (req, res) => {
  try {
    const existing = getServiceById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Service introuvable.' });

    const { name, duration, description, price } = req.body;

    let priceCents = existing.price_cents;
    if (price !== undefined && price !== null && price !== '') {
      const normalized = String(price).replace(',', '.').replace(/[^0-9.]/g, '');
      const parsed = Math.round(parseFloat(normalized) * 100);
      if (!Number.isFinite(parsed) || parsed < 0) {
        return res.status(400).json({ error: 'Prix invalide.' });
      }
      priceCents = parsed;
    }

    const newName = (name !== undefined && name !== null && name.trim() !== '') ? name.trim() : existing.name;
    const newDuration = (duration !== undefined && duration !== null && duration.trim() !== '') ? duration.trim() : existing.duration;
    const newDescription = (description !== undefined && description !== null) ? description.trim() : existing.description;

    db.prepare(`
      UPDATE services SET name = ?, duration = ?, description = ?, price_cents = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(newName, newDuration, newDescription, priceCents, req.params.id);

    const updated = getServiceById(req.params.id);
    res.json({ success: true, service: publicService(updated) });
  } catch (err) {
    console.error('Erreur mise à jour service :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la mise à jour du service.' });
  }
});

// Création d'un nouveau service dans le catalogue.
// Limité à MAX_ACTIVE_SERVICES services actifs en même temps : Pierre-Olivier doit
// d'abord désactiver un service existant si elle a déjà atteint la limite.
app.post('/api/admin/services', requireAdmin, (req, res) => {
  try {
    const { name, duration, description, price } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).json({ error: 'Le nom du service est requis.' });
    }
    if (!duration || !String(duration).trim()) {
      return res.status(400).json({ error: 'La durée du service est requise.' });
    }

    const normalizedPrice = String(price ?? '').replace(',', '.').replace(/[^0-9.]/g, '');
    const priceCents = Math.round(parseFloat(normalizedPrice) * 100);
    if (!Number.isFinite(priceCents) || priceCents < 0) {
      return res.status(400).json({ error: 'Prix invalide.' });
    }

    const activeCount = db.prepare('SELECT COUNT(*) as n FROM services WHERE active = 1').get().n;
    if (activeCount >= MAX_ACTIVE_SERVICES) {
      return res.status(400).json({
        error: `Limite atteinte : ${MAX_ACTIVE_SERVICES} services actifs maximum. Désactivez-en un avant d'en ajouter un nouveau.`,
      });
    }

    const maxOrder = db.prepare('SELECT COALESCE(MAX(sort_order), -1) as m FROM services').get().m;

    const result = db.prepare(`
      INSERT INTO services (sort_order, name, duration, description, price_cents, active)
      VALUES (?, ?, ?, ?, ?, 1)
    `).run(maxOrder + 1, String(name).trim(), String(duration).trim(), description ? String(description).trim() : '', priceCents);

    const created = getServiceById(result.lastInsertRowid);
    res.json({ success: true, service: publicService(created) });
  } catch (err) {
    console.error('Erreur création service :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la création du service.' });
  }
});

// Désactivation (« suppression douce ») d'un service.
// Le service disparaît du site et des nouvelles réservations possibles,
// mais reste en base pour ne pas casser l'historique des réservations
// déjà prises (qui référencent le nom/prix au moment de la réservation).
app.delete('/api/admin/services/:id', requireAdmin, (req, res) => {
  try {
    const existing = getServiceById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Service introuvable.' });

    db.prepare(`UPDATE services SET active = 0, updated_at = datetime('now') WHERE id = ?`).run(req.params.id);

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur désactivation service :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la désactivation du service.' });
  }
});

// Réactivation d'un service précédemment désactivé (utile si Pierre-Olivier change
// d'avis), tant que la limite de services actifs n'est pas dépassée.
app.post('/api/admin/services/:id/reactivate', requireAdmin, (req, res) => {
  try {
    const existing = getServiceById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Service introuvable.' });

    const activeCount = db.prepare('SELECT COUNT(*) as n FROM services WHERE active = 1').get().n;
    if (activeCount >= MAX_ACTIVE_SERVICES) {
      return res.status(400).json({
        error: `Limite atteinte : ${MAX_ACTIVE_SERVICES} services actifs maximum. Désactivez-en un avant de réactiver celui-ci.`,
      });
    }

    db.prepare(`UPDATE services SET active = 1, updated_at = datetime('now') WHERE id = ?`).run(req.params.id);
    const updated = getServiceById(req.params.id);
    res.json({ success: true, service: publicService(updated) });
  } catch (err) {
    console.error('Erreur réactivation service :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la réactivation du service.' });
  }
});

// ============================================================
// TÉMOIGNAGES — soumission par les clientes + modération admin
// ============================================================

// Liste publique : uniquement les témoignages approuvés par Pierre-Olivier,
// les plus récents en premier.
app.get('/api/testimonials', (req, res) => {
  const rows = db.prepare(`
    SELECT testimonials.id, testimonials.rating, testimonials.quote, testimonials.created_at, users.name as author_name
    FROM testimonials JOIN users ON users.id = testimonials.user_id
    WHERE testimonials.status = 'approuve'
    ORDER BY testimonials.created_at DESC
  `).all();
  res.json(rows);
});

// Soumission d'un témoignage par une cliente connectée.
// Le témoignage part toujours en statut "en_attente" : il ne sera visible
// publiquement qu'une fois approuvé par Pierre-Olivier depuis l'espace admin.
app.post('/api/testimonials', requireAuth, async (req, res) => {
  try {
    const { rating, quote } = req.body;

    const parsedRating = Number(rating);
    if (!Number.isInteger(parsedRating) || parsedRating < 1 || parsedRating > 5) {
      return res.status(400).json({ error: 'La note doit être un nombre entier entre 1 et 5.' });
    }
    if (!quote || !String(quote).trim()) {
      return res.status(400).json({ error: 'Le témoignage ne peut pas être vide.' });
    }
    const trimmedQuote = String(quote).trim();
    if (trimmedQuote.length > 1000) {
      return res.status(400).json({ error: 'Le témoignage est trop long (1000 caractères maximum).' });
    }

    const result = db.prepare(`
      INSERT INTO testimonials (user_id, rating, quote, status) VALUES (?, ?, ?, 'en_attente')
    `).run(req.session.userId, parsedRating, trimmedQuote);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    // Le témoignage est tout de même enregistré même si le courriel échoue.
    try {
      await sendNewTestimonialAlert({
        clientName: user.name,
        clientEmail: user.email,
        rating: parsedRating,
        quote: trimmedQuote,
      });
    } catch (mailErr) {
      console.error('⚠️  Erreur envoi alerte nouveau témoignage :', mailErr.message);
    }

    res.json({ success: true, testimonialId: result.lastInsertRowid });
  } catch (err) {
    console.error('Erreur création témoignage :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de l\'envoi du témoignage.' });
  }
});

// Liste complète pour l'admin (tous statuts), pour la modération.
app.get('/api/admin/testimonials', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT testimonials.*, users.name as author_name, users.email as author_email
    FROM testimonials JOIN users ON users.id = testimonials.user_id
    ORDER BY
      CASE testimonials.status WHEN 'en_attente' THEN 0 ELSE 1 END,
      testimonials.created_at DESC
  `).all();
  res.json(rows);
});

// Approbation ou rejet d'un témoignage par Pierre-Olivier.
app.post('/api/admin/testimonials/:id/status', requireAdmin, (req, res) => {
  const { status } = req.body;
  if (!['approuve', 'rejete', 'en_attente'].includes(status)) {
    return res.status(400).json({ error: 'Statut invalide.' });
  }
  const existing = db.prepare('SELECT id FROM testimonials WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Témoignage introuvable.' });

  db.prepare(`UPDATE testimonials SET status = ?, reviewed_at = datetime('now') WHERE id = ?`).run(status, req.params.id);
  res.json({ success: true });
});

// Suppression définitive d'un témoignage (ex. contenu inapproprié).
app.delete('/api/admin/testimonials/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM testimonials WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// FIL DE CONVERSATION — réservé aux clientes connectées (compte requis)
// ============================================================

// Récupère (ou crée) la conversation de la cliente connectée et tous ses messages.
app.get('/api/conversation', requireAuth, (req, res) => {
  let conversation = db.prepare('SELECT * FROM conversations WHERE user_id = ?').get(req.session.userId);
  if (!conversation) {
    return res.json({ conversation: null, messages: [] });
  }

  const messages = db.prepare(`
    SELECT * FROM conversation_messages WHERE conversation_id = ? ORDER BY created_at ASC
  `).all(conversation.id);

  // La cliente vient de consulter : on retire son indicateur "non lu".
  db.prepare('UPDATE conversations SET has_unread_for_client = 0 WHERE id = ?').run(conversation.id);

  res.json({ conversation, messages });
});

// Envoi d'un message par la cliente (premier message ou suite de conversation).
app.post('/api/conversation', requireAuth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !String(message).trim()) {
      return res.status(400).json({ error: 'Le message ne peut pas être vide.' });
    }
    const trimmedMessage = String(message).trim().slice(0, 5000);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

    let conversation = db.prepare('SELECT * FROM conversations WHERE user_id = ?').get(req.session.userId);
    if (!conversation) {
      const result = db.prepare(`
        INSERT INTO conversations (user_id, has_unread_for_admin, has_unread_for_client) VALUES (?, 1, 0)
      `).run(req.session.userId);
      conversation = db.prepare('SELECT * FROM conversations WHERE id = ?').get(result.lastInsertRowid);
    } else {
      db.prepare(`
        UPDATE conversations SET has_unread_for_admin = 1, updated_at = datetime('now') WHERE id = ?
      `).run(conversation.id);
    }

    const msgResult = db.prepare(`
      INSERT INTO conversation_messages (conversation_id, sender, message, email_sent) VALUES (?, 'client', ?, 0)
    `).run(conversation.id, trimmedMessage);

    let emailSent = false;
    try {
      await sendConversationAlertToAdmin({ clientName: user.name, clientEmail: user.email, message: trimmedMessage });
      emailSent = true;
    } catch (mailErr) {
      console.error('⚠️  Erreur envoi courriel (nouveau message client, message tout de même enregistré) :', mailErr.message);
    }
    if (emailSent) {
      db.prepare('UPDATE conversation_messages SET email_sent = 1 WHERE id = ?').run(msgResult.lastInsertRowid);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur traitement message de conversation :', err.message);
    res.status(500).json({ error: 'Erreur lors de l\'envoi du message. Veuillez réessayer ou écrire directement à contact@3pierre6olivier9.com.' });
  }
});

// ============================================================
// ADMIN — gestion des conversations
// ============================================================

// Liste des conversations, les non lues par l'admin en premier, puis les plus récentes.
app.get('/api/admin/conversations', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT conversations.*, users.name as client_name, users.email as client_email,
      (SELECT message FROM conversation_messages WHERE conversation_id = conversations.id ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT sender FROM conversation_messages WHERE conversation_id = conversations.id ORDER BY created_at DESC LIMIT 1) as last_sender
    FROM conversations
    JOIN users ON users.id = conversations.user_id
    ORDER BY conversations.has_unread_for_admin DESC, conversations.updated_at DESC
  `).all();
  res.json(rows);
});

// Détail d'une conversation (tous les messages), avec marquage "lu" pour l'admin.
app.get('/api/admin/conversations/:id', requireAdmin, (req, res) => {
  const conversation = db.prepare(`
    SELECT conversations.*, users.name as client_name, users.email as client_email
    FROM conversations JOIN users ON users.id = conversations.user_id
    WHERE conversations.id = ?
  `).get(req.params.id);
  if (!conversation) return res.status(404).json({ error: 'Conversation introuvable.' });

  const messages = db.prepare(`
    SELECT * FROM conversation_messages WHERE conversation_id = ? ORDER BY created_at ASC
  `).all(conversation.id);

  db.prepare('UPDATE conversations SET has_unread_for_admin = 0 WHERE id = ?').run(conversation.id);

  res.json({ conversation, messages });
});

// Réponse de Pierre-Olivier dans une conversation.
app.post('/api/admin/conversations/:id/reply', requireAdmin, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !String(message).trim()) {
      return res.status(400).json({ error: 'Le message ne peut pas être vide.' });
    }
    const trimmedMessage = String(message).trim().slice(0, 5000);

    const conversation = db.prepare(`
      SELECT conversations.*, users.name as client_name, users.email as client_email
      FROM conversations JOIN users ON users.id = conversations.user_id
      WHERE conversations.id = ?
    `).get(req.params.id);
    if (!conversation) return res.status(404).json({ error: 'Conversation introuvable.' });

    const msgResult = db.prepare(`
      INSERT INTO conversation_messages (conversation_id, sender, message, email_sent) VALUES (?, 'admin', ?, 0)
    `).run(conversation.id, trimmedMessage);

    db.prepare(`
      UPDATE conversations SET has_unread_for_client = 1, updated_at = datetime('now') WHERE id = ?
    `).run(conversation.id);

    let emailSent = false;
    try {
      await sendConversationReplyToClient({ clientName: conversation.client_name, clientEmail: conversation.client_email, message: trimmedMessage });
      emailSent = true;
    } catch (mailErr) {
      console.error('⚠️  Erreur envoi courriel (réponse de Pierre-Olivier, message tout de même enregistré) :', mailErr.message);
    }
    if (emailSent) {
      db.prepare('UPDATE conversation_messages SET email_sent = 1 WHERE id = ?').run(msgResult.lastInsertRowid);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur traitement réponse admin :', err.message);
    res.status(500).json({ error: 'Erreur lors de l\'envoi de la réponse.' });
  }
});

// Suppression d'une conversation entière (et tous ses messages).
app.delete('/api/admin/conversations/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM conversation_messages WHERE conversation_id = ?').run(req.params.id);
  db.prepare('DELETE FROM conversations WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================
// DISPONIBILITÉS — gestion admin (heures d'ouverture + blocages)
// ============================================================

// Liste des 7 jours avec leurs heures d'ouverture actuelles.
app.get('/api/admin/business-hours', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM business_hours ORDER BY weekday ASC').all();
  res.json(rows);
});

// Met à jour les heures d'un jour de la semaine (0 = dimanche ... 6 = samedi).
app.put('/api/admin/business-hours/:weekday', requireAdmin, (req, res) => {
  try {
    const weekday = parseInt(req.params.weekday, 10);
    if (!Number.isInteger(weekday) || weekday < 0 || weekday > 6) {
      return res.status(400).json({ error: 'Jour de la semaine invalide.' });
    }
    const existing = getBusinessHoursForWeekday(weekday);
    if (!existing) return res.status(404).json({ error: 'Jour introuvable.' });

    const { isOpen, startTime, endTime, slotDurationMinutes, breakBetweenSlotsMinutes, breakStart, breakEnd } = req.body;

    const newIsOpen = (isOpen !== undefined) ? (isOpen ? 1 : 0) : existing.is_open;
    const newStart = startTime || existing.start_time;
    const newEnd = endTime || existing.end_time;
    const newDuration = slotDurationMinutes ? parseInt(slotDurationMinutes, 10) : existing.slot_duration_minutes;

    const ALLOWED_GAPS = [0, 30, 60, 90];
    let newGap = existing.break_between_slots_minutes;
    if (breakBetweenSlotsMinutes !== undefined) {
      const parsedGap = parseInt(breakBetweenSlotsMinutes, 10);
      if (!ALLOWED_GAPS.includes(parsedGap)) {
        return res.status(400).json({ error: 'Pause entre les créneaux invalide (0, 30, 60 ou 90 minutes).' });
      }
      newGap = parsedGap;
    }

    if (timeToMinutes(newStart) >= timeToMinutes(newEnd)) {
      return res.status(400).json({ error: 'L\'heure de début doit précéder l\'heure de fin.' });
    }

    // breakStart/breakEnd : chaîne vide ou null = pas de pause.
    const newBreakStart = (breakStart !== undefined) ? (breakStart || null) : existing.break_start;
    const newBreakEnd = (breakEnd !== undefined) ? (breakEnd || null) : existing.break_end;
    if ((newBreakStart && !newBreakEnd) || (!newBreakStart && newBreakEnd)) {
      return res.status(400).json({ error: 'La pause doit avoir une heure de début ET de fin.' });
    }

    db.prepare(`
      UPDATE business_hours
      SET is_open = ?, start_time = ?, end_time = ?, slot_duration_minutes = ?,
          break_between_slots_minutes = ?, break_start = ?, break_end = ?, updated_at = datetime('now')
      WHERE weekday = ?
    `).run(newIsOpen, newStart, newEnd, newDuration, newGap, newBreakStart, newBreakEnd, weekday);

    res.json({ success: true, businessHours: getBusinessHoursForWeekday(weekday) });
  } catch (err) {
    console.error('Erreur mise à jour heures d\'ouverture :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Liste des blocages à venir (vacances, fermetures, plages bloquées).
app.get('/api/admin/blocked-periods', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM blocked_periods WHERE blocked_date >= date('now') ORDER BY blocked_date ASC, start_time ASC
  `).all();
  res.json(rows);
});

// Crée un ou plusieurs blocages en une seule opération : jour complet
// (startTime/endTime omis) ou plage précise. Accepte soit { blockedDate }
// pour un seul jour (rétrocompatibilité), soit { blockedDates: [...] } pour
// bloquer plusieurs dates d'un coup avec le même motif/plage horaire.
app.post('/api/admin/blocked-periods', requireAdmin, (req, res) => {
  try {
    const { blockedDate, blockedDates, startTime, endTime, reason } = req.body;

    // Normalise en tableau de dates, sans doublons, sans valeurs vides.
    let dates = Array.isArray(blockedDates) ? blockedDates.filter(Boolean) : [];
    if (blockedDate) dates.push(blockedDate);
    dates = [...new Set(dates)];

    if (dates.length === 0) return res.status(400).json({ error: 'Veuillez choisir au moins une date.' });

    if ((startTime && !endTime) || (!startTime && endTime)) {
      return res.status(400).json({ error: 'Indiquez une heure de début ET de fin, ou laissez les deux vides pour bloquer la journée complète.' });
    }
    if (startTime && endTime && timeToMinutes(startTime) >= timeToMinutes(endTime)) {
      return res.status(400).json({ error: 'L\'heure de début doit précéder l\'heure de fin.' });
    }

    const insert = db.prepare(`
      INSERT INTO blocked_periods (blocked_date, start_time, end_time, reason)
      VALUES (?, ?, ?, ?)
    `);
    const insertMany = db.transaction((dateList) => {
      const ids = [];
      for (const d of dateList) {
        const result = insert.run(d, startTime || null, endTime || null, (reason || '').trim());
        ids.push(result.lastInsertRowid);
      }
      return ids;
    });
    const ids = insertMany(dates);

    res.json({ success: true, ids, count: ids.length });
  } catch (err) {
    console.error('Erreur création blocage :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Supprime un blocage (Pierre-Olivier change d'avis / erreur de saisie).
app.delete('/api/admin/blocked-periods/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM blocked_periods WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});



// ============================================================
// TEXTES MODIFIABLES — pages Accueil et À propos
// ============================================================
// Liste des clés autorisées : toute clé hors de cette liste est rejetée par
// la route d'enregistrement, pour éviter qu'un appel malformé ne crée des
// entrées orphelines en base.
const SITE_CONTENT_KEYS = Object.keys(SITE_CONTENT_DEFAULTS);

// Accessible à tout le monde : permet au frontend de connaître la version
// actuelle de la politique de confidentialité, affichée dans la fenêtre de
// consentement à l'inscription.
app.get('/api/privacy-policy-version', (req, res) => {
  res.json({ version: getPrivacyPolicyVersion() });
});

// Accessible à tout le monde : le site charge ces textes pour afficher
// les pages Accueil et À propos avec le contenu actuel (modifié ou par défaut).
app.get('/api/site-content', (req, res) => {
  res.json(getSiteContent());
});

// Admin seulement : liste les textes actuels (identique à la route publique,
// mais group separately for clarity dans le panneau admin).
app.get('/api/admin/site-content', requireAdmin, (req, res) => {
  res.json(getSiteContent());
});

// Admin seulement : enregistre un lot de modifications de texte. Le corps
// attendu est un objet { clé: valeur, ... } — seules les clés reconnues
// (SITE_CONTENT_KEYS) sont prises en compte, le reste est silencieusement ignoré.
app.put('/api/admin/site-content', requireAdmin, (req, res) => {
  try {
    const updates = req.body || {};
    const upsert = db.prepare(`
      INSERT INTO site_content (key, value, updated_at) VALUES (?, ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
    `);
    const tx = db.transaction((entries) => {
      for (const [key, value] of entries) {
        if (!SITE_CONTENT_KEYS.includes(key)) continue;
        upsert.run(key, String(value ?? ''));
      }
    });
    tx(Object.entries(updates));
    bumpPrivacyPolicyVersionIfNeeded(Object.keys(updates).filter((k) => SITE_CONTENT_KEYS.includes(k)));
    res.json({ success: true, content: getSiteContent(), privacyPolicyVersion: getPrivacyPolicyVersion() });
  } catch (err) {
    console.error('Erreur mise à jour des textes du site :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de l\'enregistrement.' });
  }
});

// ============================================================
// IMAGES MODIFIABLES — remplace les emplacements « Image à venir »
// ============================================================
// Liste des emplacements autorisés : toute clé hors de cette liste est
// rejetée par les routes d'upload/suppression, pour éviter la création
// d'entrées orphelines en base.
const SITE_IMAGE_KEYS = [
  'home_img_1', 'home_img_2', 'home_img_3', 'home_img_4',
  'about_img_1', 'about_img_2', 'about_img_3',
  'services_img_1',
];

const SITE_IMAGE_ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];
const SITE_IMAGE_MAX_BYTES = 8 * 1024 * 1024; // 8 Mo

const siteImageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: SITE_IMAGE_MAX_BYTES },
  fileFilter: (req, file, cb) => {
    if (!SITE_IMAGE_ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new Error('Format d\'image non supporté (JPEG, PNG ou WEBP seulement).'));
    }
    cb(null, true);
  },
});

function getSiteImages() {
  const rows = db.prepare('SELECT key, mime_type, data_base64 FROM site_images').all();
  const images = {};
  for (const row of rows) {
    images[row.key] = `data:${row.mime_type};base64,${row.data_base64}`;
  }
  return images;
}

// Accessible à tout le monde : le site charge les images actuellement en
// place pour chaque emplacement (celles non encore remplacées sont
// simplement absentes de la réponse, et le placeholder reste affiché).
app.get('/api/site-images', (req, res) => {
  try {
    res.json(getSiteImages());
  } catch (err) {
    console.error('Erreur lors du chargement des images du site :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Admin seulement : liste identique à la route publique, regroupée à part
// pour plus de clarté dans le panneau admin.
app.get('/api/admin/site-images', requireAdmin, (req, res) => {
  try {
    res.json(getSiteImages());
  } catch (err) {
    console.error('Erreur lors du chargement des images du site :', err.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Admin seulement : upload ou remplacement d'une image pour un emplacement
// donné. Le corps de la requête doit être multipart/form-data avec un champ
// "image".
app.post('/api/admin/site-images/:key', requireAdmin, (req, res) => {
  siteImageUpload.single('image')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Erreur lors du téléversement.' });
    }
    try {
      const { key } = req.params;
      if (!SITE_IMAGE_KEYS.includes(key)) {
        return res.status(400).json({ error: 'Emplacement d\'image inconnu.' });
      }
      if (!req.file) {
        return res.status(400).json({ error: 'Aucune image reçue.' });
      }
      const base64 = req.file.buffer.toString('base64');
      db.prepare(`
        INSERT INTO site_images (key, mime_type, data_base64, updated_at) VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET mime_type = excluded.mime_type, data_base64 = excluded.data_base64, updated_at = datetime('now')
      `).run(key, req.file.mimetype, base64);
      res.json({ success: true, key, image: `data:${req.file.mimetype};base64,${base64}` });
    } catch (err2) {
      console.error('Erreur lors de l\'enregistrement de l\'image :', err2.message);
      res.status(500).json({ error: 'Erreur serveur lors de l\'enregistrement.' });
    }
  });
});

// Admin seulement : retire une image d'un emplacement (le placeholder
// « Image à venir » réapparaît alors sur le site).
app.delete('/api/admin/site-images/:key', requireAdmin, (req, res) => {
  try {
    const { key } = req.params;
    if (!SITE_IMAGE_KEYS.includes(key)) {
      return res.status(400).json({ error: 'Emplacement d\'image inconnu.' });
    }
    db.prepare('DELETE FROM site_images WHERE key = ?').run(key);
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur lors de la suppression de l\'image :', err.message);
    res.status(500).json({ error: 'Erreur serveur lors de la suppression.' });
  }
});


// ============================================================
// Rendez-vous proposés : réponse Accepter/Refuser (sans connexion requise)
// ============================================================
// Design volontaire : les liens du courriel mènent d'abord à une page qui
// demande un second geste explicite (bouton) avant d'enregistrer quoi que ce
// soit. Un lien qui agirait directement au clic serait déclenché par erreur
// par les scanners anti-pourriel de plusieurs boîtes courriel, qui visitent
// automatiquement les liens reçus — ce qui annulerait ou confirmerait des
// rendez-vous à l'insu de la cliente.

function renderResponsePageShell(bodyHtml) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Votre rendez-vous — Pierre-Olivier Doucet</title>
<style>
  body { font-family: Georgia, serif; background:#FAF6F0; color:#352B28; margin:0; padding:40px 20px; }
  .card { max-width:480px; margin:0 auto; background:#fff; border-radius:16px; padding:32px; box-shadow:0 2px 12px rgba(0,0,0,0.06); }
  h1 { color:#A87C2E; font-size:22px; margin-top:0; }
  table { width:100%; border-collapse:collapse; margin:16px 0; font-family:-apple-system,sans-serif; font-size:14px; }
  td { padding:6px 0; }
  td:first-child { color:#8A7A74; }
  td:last-child { text-align:right; }
  .btn { display:inline-block; padding:12px 28px; border-radius:10px; text-decoration:none; font-family:-apple-system,sans-serif; font-weight:600; margin:8px 6px; border:none; cursor:pointer; font-size:15px; }
  .btn-accept { background:#3E7C59; color:#fff; }
  .btn-refuse { background:#fff; color:#B3261E; border:1px solid #B3261E; }
  .btn-neutral { background:#A87C2E; color:#fff; }
  .actions { text-align:center; margin-top:24px; }
  p { font-family:-apple-system,sans-serif; font-size:14px; line-height:1.6; }
</style>
</head>
<body>
  <div class="card">${bodyHtml}</div>
</body>
</html>`;
}

function renderTokenErrorPage() {
  return renderResponsePageShell(`
    <h1>Lien invalide ou déjà utilisé</h1>
    <p>Ce lien de réponse n'est plus valide — il a peut-être déjà été utilisé, ou il a expiré (les liens sont valides ${ACCEPT_TOKEN_VALIDITY_DAYS} jours).</p>
    <p>Si vous attendez toujours une réponse à donner sur un rendez-vous, contactez directement Pierre-Olivier à <strong>${escapeHtml(process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com')}</strong>.</p>
  `);
}

function renderProposalConfirmPage(record, token, action) {
  const isAccept = action === 'accepter';
  return renderResponsePageShell(`
    <h1>${isAccept ? 'Confirmer votre présence' : 'Refuser ce rendez-vous'}</h1>
    <p>Bonjour ${escapeHtml(record.client_name)},</p>
    <table>
      <tr><td>Service</td><td>${escapeHtml(record.service_name)}</td></tr>
      <tr><td>Date</td><td>${escapeHtml(record.booking_date_label)}</td></tr>
      <tr><td>Heure</td><td>${escapeHtml(record.booking_time)}</td></tr>
    </table>
    <p>${isAccept
      ? 'Cliquez ci-dessous pour confirmer que ce rendez-vous vous convient.'
      : 'Cliquez ci-dessous pour confirmer que vous refusez ce rendez-vous. Pierre-Olivier sera avisé et vous recontactera.'}</p>
    <form method="POST" action="/rdv/repondre" class="actions">
      <input type="hidden" name="token" value="${escapeHtml(token)}">
      <input type="hidden" name="action" value="${isAccept ? 'accepter' : 'refuser'}">
      <button type="submit" class="btn ${isAccept ? 'btn-accept' : 'btn-refuse'}">${isAccept ? 'Oui, je confirme ma présence' : 'Oui, je refuse ce rendez-vous'}</button>
    </form>
    <p style="text-align:center;"><a href="/rdv/repondre?token=${encodeURIComponent(token)}&action=${isAccept ? 'refuser' : 'accepter'}" style="color:#8A7A74;">${isAccept ? "Plutôt refuser ce rendez-vous" : "Plutôt accepter ce rendez-vous"}</a></p>
  `);
}

function renderAcceptedResultPage(record) {
  return renderResponsePageShell(`
    <h1>Rendez-vous confirmé ✦</h1>
    <p>Merci ${escapeHtml(record.client_name)}, votre présence est confirmée pour le <strong>${escapeHtml(record.booking_date_label)}</strong> à <strong>${escapeHtml(record.booking_time)}</strong>.</p>
    <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
  `);
}

function renderRefusedResultPage(record) {
  return renderResponsePageShell(`
    <h1>Rendez-vous refusé</h1>
    <p>C'est noté ${escapeHtml(record.client_name)} — ce rendez-vous du ${escapeHtml(record.booking_date_label)} à ${escapeHtml(record.booking_time)} est annulé.</p>
    <p>Pierre-Olivier a été avisé et vous recontactera pour trouver un autre moment si vous le souhaitez.</p>
  `);
}

// Page affichée au clic sur le lien du courriel — demande confirmation avant
// d'agir. Le jeton n'est validé/consommé qu'à l'étape POST suivante.
app.get('/rdv/repondre', (req, res) => {
  const { token, action } = req.query;
  const record = findPendingBookingByToken(token);
  if (!record || !['accepter', 'refuser'].includes(action)) {
    return res.status(400).send(renderTokenErrorPage());
  }
  res.send(renderProposalConfirmPage(record, token, action));
});

// Enregistre la décision de la cliente. Jeton à usage unique : une fois
// consommé (accept_token_hash mis à NULL), il ne peut plus être réutilisé.
app.post('/rdv/repondre', async (req, res) => {
  const { token, action } = req.body || {};
  const record = findPendingBookingByToken(token);
  if (!record || !['accepter', 'refuser'].includes(action)) {
    return res.status(400).send(renderTokenErrorPage());
  }

  const adminAddress = process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com';
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';

  if (action === 'accepter') {
    const newStatus = record.previous_status || 'en_attente';
    db.prepare(`
      UPDATE bookings SET status = ?, responded_at = datetime('now'), accept_token_hash = NULL, accept_token_expires_at = NULL
      WHERE id = ?
    `).run(newStatus, record.id);
    if (record.program_id) refreshProgramStatus(record.program_id);

    try {
      await resend.emails.send({
        from: fromAddress,
        to: adminAddress,
        subject: `Rendez-vous accepté : ${record.client_name}`,
        html: `<div style="font-family:Georgia,serif;color:#352B28;"><p><strong>${escapeHtml(record.client_name)}</strong> (${escapeHtml(record.client_email)}) a accepté le rendez-vous du ${escapeHtml(record.booking_date_label)} à ${escapeHtml(record.booking_time)} (${escapeHtml(record.service_name)}).</p></div>`,
      });
    } catch (emailErr) {
      console.error('⚠️  Erreur notification admin (acceptation) :', emailErr.message);
    }

    return res.send(renderAcceptedResultPage(record));
  }

  // action === 'refuser'
  db.prepare(`
    UPDATE bookings SET status = 'annule', responded_at = datetime('now'), accept_token_hash = NULL, accept_token_expires_at = NULL
    WHERE id = ?
  `).run(record.id);
  if (record.program_id) refreshProgramStatus(record.program_id);

  try {
    await resend.emails.send({
      from: fromAddress,
      to: adminAddress,
      subject: `Rendez-vous refusé : ${record.client_name}`,
      html: `<div style="font-family:Georgia,serif;color:#352B28;"><p><strong>${escapeHtml(record.client_name)}</strong> (${escapeHtml(record.client_email)}) a refusé le rendez-vous du ${escapeHtml(record.booking_date_label)} à ${escapeHtml(record.booking_time)} (${escapeHtml(record.service_name)}). Il a été annulé automatiquement.</p></div>`,
    });
  } catch (emailErr) {
    console.error('⚠️  Erreur notification admin (refus) :', emailErr.message);
  }

  res.send(renderRefusedResultPage(record));
});

// ============================================================
// Envoi des emails de confirmation via Resend
// ============================================================
async function sendConfirmationEmails({ clientName, clientEmail, service, bookingDateLabel, bookingTime, paymentMethod, status, notifyAdmin = true }) {
  const methodLabel = paymentMethod === 'carte' ? 'Carte bancaire' : 'Virement Interac';
  const statusLabel = status === 'confirme'
    ? 'Confirmée'
    : status === 'annule'
      ? 'Annulée'
      : 'En attente de paiement';

  let clientBodyHtml;
  if (status === 'confirme') {
    clientBodyHtml = `
      <p>Bonne nouvelle ${escapeHtml(clientName)}, votre rendez-vous est confirmé ! ✦</p>
      <table style="width:100%;border-collapse:collapse;margin:16px 0;">
        <tr><td style="padding:6px 0;color:#8A7A74;">Service</td><td style="padding:6px 0;text-align:right;">${escapeHtml(service.name)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Date</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingDateLabel)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Heure</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingTime)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Paiement</td><td style="padding:6px 0;text-align:right;">${methodLabel}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;font-weight:bold;">Total</td><td style="padding:6px 0;text-align:right;font-weight:bold;">${service.price}</td></tr>
      </table>
      <p>Vous pouvez consulter ou annuler ce rendez-vous depuis votre profil sur le site.</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    `;
  } else if (status === 'annule') {
    clientBodyHtml = `
      <p>Bonjour ${escapeHtml(clientName)},</p>
      <p>Votre rendez-vous du <strong>${escapeHtml(bookingDateLabel)}</strong> à <strong>${escapeHtml(bookingTime)}</strong> pour <strong>${escapeHtml(service.name)}</strong> a été annulé.</p>
      <p>N'hésitez pas à reprendre rendez-vous depuis le site quand vous le souhaitez.</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    `;
  } else {
    clientBodyHtml = `
      <p>Bonjour ${escapeHtml(clientName)},</p>
      <table style="width:100%;border-collapse:collapse;margin:16px 0;">
        <tr><td style="padding:6px 0;color:#8A7A74;">Service</td><td style="padding:6px 0;text-align:right;">${escapeHtml(service.name)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Date</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingDateLabel)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Heure</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingTime)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Paiement</td><td style="padding:6px 0;text-align:right;">${methodLabel}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;font-weight:bold;">Total</td><td style="padding:6px 0;text-align:right;font-weight:bold;">${service.price}</td></tr>
      </table>
      ${paymentMethod === 'interac'
        ? '<p>Merci d\'envoyer votre virement Interac à <strong>paiement@3pierre6olivier9.com</strong> pour confirmer votre rendez-vous.</p>'
        : ''}
      <p>Vous pouvez consulter ou annuler ce rendez-vous depuis votre profil sur le site.</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    `;
  }

  const clientHtml = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h2 style="color:#A87C2E;">Votre réservation — ${statusLabel} ✦</h2>
      ${clientBodyHtml}
    </div>
  `;

  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';

  console.log('\n📧 [DEBUG] Envoi du courriel de confirmation au client');
  console.log('📧 [DEBUG] EMAIL_FROM utilisé   :', fromAddress);
  console.log('📧 [DEBUG] Destinataire (client) :', clientEmail);

  try {
    const clientResult = await resend.emails.send({ from: fromAddress, to: clientEmail, subject: `Votre réservation — ${statusLabel} — Pierre-Olivier Doucet`, html: clientHtml });
    console.log('📧 [DEBUG] Réponse Resend (client) :', JSON.stringify(clientResult));
  } catch (sendErr) {
    console.error('❌ [DEBUG] Erreur Resend (client) :', sendErr);
  }

  if (notifyAdmin) {
    const adminAddress = process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com';
    const adminHtml = `
      <div style="font-family:Georgia,serif;color:#352B28;">
        <h3>Nouvelle réservation en attente de virement Interac</h3>
        <p><strong>${escapeHtml(clientName)}</strong> (${escapeHtml(clientEmail)})</p>
        <p>${escapeHtml(service.name)} — ${escapeHtml(bookingDateLabel)} à ${escapeHtml(bookingTime)}</p>
        <p>Montant attendu : <strong>${service.price}</strong></p>
        <p>Vérifiez la réception du virement Interac, puis confirmez (ou annulez) cette réservation depuis l'espace admin du site.</p>
      </div>
    `;
    console.log('📧 [DEBUG] Destinataire (admin)  :', adminAddress);
    try {
      const adminResult = await resend.emails.send({ from: fromAddress, to: adminAddress, subject: `Nouvelle réservation : ${service.name}`, html: adminHtml });
      console.log('📧 [DEBUG] Réponse Resend (admin) :', JSON.stringify(adminResult));
    } catch (sendErr) {
      console.error('❌ [DEBUG] Erreur Resend (admin) :', sendErr);
    }
  }
}

// ============================================================
// Courriel de rappel — envoyé 24h avant un rendez-vous confirmé
// ============================================================
async function sendReminderEmail({ clientName, clientEmail, serviceName, bookingDateLabel, bookingTime }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h2 style="color:#A87C2E;">Rappel de votre rendez-vous ✦</h2>
      <p>Bonjour ${escapeHtml(clientName)},</p>
      <p>Petit rappel : votre rendez-vous a lieu <strong>demain</strong>.</p>
      <table style="width:100%;border-collapse:collapse;margin:16px 0;">
        <tr><td style="padding:6px 0;color:#8A7A74;">Service</td><td style="padding:6px 0;text-align:right;">${escapeHtml(serviceName)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Date</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingDateLabel)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Heure</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingTime)}</td></tr>
      </table>
      <p>Si vous devez annuler ou modifier ce rendez-vous, vous pouvez le faire depuis votre profil sur le site, dans « Mes rendez-vous ».</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: clientEmail,
    subject: 'Rappel : votre rendez-vous est demain — Pierre-Olivier Doucet',
    html,
  });
}

// ============================================================
// Alerte admin : tentative d'inscription avec un âge inférieur à 18 ans
// ============================================================
async function sendUnderageAttemptAlert({ email, name, birthDate }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';
  const adminAddress = process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com';

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;">
      <h3 style="color:#B3261E;">⚠️ Tentative d'inscription refusée — âge minimum non respecté</h3>
      <p>Une tentative de création de compte a été automatiquement refusée car la personne a indiqué un âge inférieur à 18 ans.</p>
      <table style="border-collapse:collapse;margin:12px 0;">
        <tr><td style="padding:4px 12px 4px 0;color:#8A7A74;">Nom fourni</td><td style="padding:4px 0;">${escapeHtml(name)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#8A7A74;">Courriel</td><td style="padding:4px 0;">${escapeHtml(email)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#8A7A74;">Date de naissance fournie</td><td style="padding:4px 0;">${escapeHtml(birthDate)}</td></tr>
      </table>
      <p>Cette adresse courriel a été bloquée automatiquement et ne pourra plus créer de compte sur le site.</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: adminAddress,
    subject: `Inscription refusée (âge) — ${email}`,
    html,
  });
}

// ============================================================
// Courriel : alerte à Pierre-Olivier lors d'un nouveau témoignage à modérer
// ============================================================
async function sendNewTestimonialAlert({ clientName, clientEmail, rating, quote }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';
  const adminAddress = process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com';

  const stars = '★'.repeat(rating) + '☆'.repeat(5 - rating);

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h3 style="color:#A87C2E;">Nouveau témoignage à approuver ✦</h3>
      <p><strong>${escapeHtml(clientName)}</strong> (${escapeHtml(clientEmail)})</p>
      <p style="color:#A87C2E;letter-spacing:2px;">${stars}</p>
      <p style="font-style:italic;border-left:3px solid #E8DCC8;padding-left:12px;">${escapeHtml(quote)}</p>
      <p>Connectez-vous à l'espace admin du site pour approuver ou rejeter ce témoignage avant qu'il ne soit visible publiquement.</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: adminAddress,
    subject: `Nouveau témoignage à modérer — ${clientName}`,
    html,
  });
}

// ============================================================
// Courriel : nouveau message d'une cliente dans le fil de conversation (vers Pierre-Olivier)
// ============================================================
async function sendConversationAlertToAdmin({ clientName, clientEmail, message }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';
  const adminAddress = process.env.ADMIN_EMAIL || 'contact@3pierre6olivier9.com';

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h3 style="color:#A87C2E;">Nouveau message — ${escapeHtml(clientName)} ✦</h3>
      <p><a href="mailto:${escapeHtml(clientEmail)}" style="color:#A87C2E;">${escapeHtml(clientEmail)}</a></p>
      <p style="white-space:pre-wrap;border-left:3px solid #E8DCC8;padding-left:12px;margin-top:16px;">${escapeHtml(message)}</p>
      <p style="margin-top:20px;font-size:13px;color:#8A7A74;">Connectez-vous à l'espace admin pour répondre directement dans la conversation.</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: adminAddress,
    replyTo: clientEmail,
    subject: `Nouveau message — ${clientName}`,
    html,
  });
}

// ============================================================
// Courriel : réponse de Pierre-Olivier dans le fil de conversation (vers la cliente)
// ============================================================
async function sendConversationReplyToClient({ clientName, clientEmail, message }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h3 style="color:#A87C2E;">Nouvelle réponse de Pierre-Olivier ✦</h3>
      <p>Bonjour ${escapeHtml(clientName)},</p>
      <p style="white-space:pre-wrap;border-left:3px solid #E8DCC8;padding-left:12px;margin-top:16px;">${escapeHtml(message)}</p>
      <p style="margin-top:20px;font-size:13px;color:#8A7A74;">Connectez-vous à votre profil sur le site pour répondre directement dans la conversation.</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: clientEmail,
    subject: `Pierre-Olivier Doucet vous a répondu`,
    html,
  });
}

// ============================================================
// Courriel : lien de réinitialisation du mot de passe
// ============================================================
async function sendPasswordResetEmail({ name, email, rawToken }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';
  // SITE_URL doit être défini dans .env (ex: https://www.3pierre6olivier9.com). En son
  // absence, on retombe sur localhost pour les tests en local.
  const siteUrl = process.env.SITE_URL || 'http://localhost:3000';
  const resetLink = `${siteUrl}/?reset=${rawToken}`;

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h2 style="color:#A87C2E;">Réinitialisation de votre mot de passe ✦</h2>
      <p>Bonjour ${escapeHtml(name)},</p>
      <p>Une demande de réinitialisation de mot de passe a été faite pour votre compte. Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe :</p>
      <p style="text-align:center;margin:28px 0;">
        <a href="${resetLink}" style="background:#A87C2E;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-family:-apple-system,sans-serif;font-weight:600;display:inline-block;">Réinitialiser mon mot de passe</a>
      </p>
      <p style="font-size:13px;color:#8A7A74;">Ce lien est valide pendant 1 heure. Si vous n'avez pas demandé cette réinitialisation, vous pouvez ignorer ce courriel sans crainte : votre mot de passe actuel reste inchangé.</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: email,
    subject: 'Réinitialisation de votre mot de passe — Pierre-Olivier Doucet',
    html,
  });
}

// ============================================================
// Courriel : proposition de rendez-vous (nouveau ou reporté) — Accepter/Refuser
// ============================================================
async function sendAppointmentProposalEmail({ clientName, clientEmail, service, bookingDateLabel, bookingTime, token, isReschedule }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';
  const siteUrl = process.env.SITE_URL || 'http://localhost:3000';
  const acceptUrl = `${siteUrl}/rdv/repondre?token=${encodeURIComponent(token)}&action=accepter`;
  const refuseUrl = `${siteUrl}/rdv/repondre?token=${encodeURIComponent(token)}&action=refuser`;

  const title = isReschedule ? 'Nouvelle date proposée pour votre rendez-vous' : 'Proposition de rendez-vous';
  const intro = isReschedule
    ? 'Pierre-Olivier vous propose de reporter votre rendez-vous à une nouvelle date :'
    : 'Pierre-Olivier vous propose un rendez-vous :';

  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h2 style="color:#A87C2E;">${title} ✦</h2>
      <p>Bonjour ${escapeHtml(clientName)},</p>
      <p>${intro}</p>
      <table style="width:100%;border-collapse:collapse;margin:16px 0;">
        <tr><td style="padding:6px 0;color:#8A7A74;">Service</td><td style="padding:6px 0;text-align:right;">${escapeHtml(service.name)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Date</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingDateLabel)}</td></tr>
        <tr><td style="padding:6px 0;color:#8A7A74;">Heure</td><td style="padding:6px 0;text-align:right;">${escapeHtml(bookingTime)}</td></tr>
      </table>
      <p>Merci de confirmer votre disponibilité :</p>
      <p style="text-align:center;margin:28px 0;">
        <a href="${acceptUrl}" style="background:#3E7C59;color:#fff;padding:12px 24px;border-radius:10px;text-decoration:none;font-family:-apple-system,sans-serif;font-weight:600;display:inline-block;margin:4px;">Accepter</a>
        <a href="${refuseUrl}" style="background:#fff;color:#B3261E;border:1px solid #B3261E;padding:12px 24px;border-radius:10px;text-decoration:none;font-family:-apple-system,sans-serif;font-weight:600;display:inline-block;margin:4px;">Refuser</a>
      </p>
      <p style="font-size:13px;color:#8A7A74;">Ce lien est valide pendant ${ACCEPT_TOKEN_VALIDITY_DAYS} jours et à usage unique. Un clic mène à une page de confirmation — rien n'est enregistré tant que vous n'y confirmez pas votre choix.</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    </div>
  `;

  await resend.emails.send({
    from: fromAddress,
    to: clientEmail,
    subject: `${title} — Pierre-Olivier Doucet`,
    html,
  });
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ============================================================
// CYCLE DE VIE DES DONNÉES — Loi 25 / PIPEDA
// ============================================================
// Durées de conservation choisies avec Pierre-Olivier :
//  - Rendez-vous : 18 mois (besoin comptable/fiscal réel), au-delà de quoi
//    ils sont supprimés même si le compte client reste actif.
//  - Comptes clients inactifs : avertis à 170 jours, supprimés à 183 jours
//    sans aucune activité (connexion ou requête authentifiée).
const BOOKING_RETENTION_DAYS = 18 * 30; // 18 mois ≈ 540 jours
const INACTIVITY_WARNING_DAYS = 170;
const INACTIVITY_DELETE_DAYS = 183;

function logRetentionEvent(eventType, detail) {
  try {
    db.prepare(`INSERT INTO data_retention_log (event_type, detail) VALUES (?, ?)`).run(eventType, detail || '');
  } catch (e) {
    console.error('⚠️  Erreur journal de rétention :', e.message);
  }
}

// Supprime intégralement un compte client et toutes les données qui s'y
// rattachent directement (réservations, conversation, témoignages, jetons
// de réinitialisation). Les enregistrements de consentement sont
// volontairement conservés (avec user_id mis à NULL) : ils constituent une
// preuve historique du consentement donné, indépendante de l'existence du compte.
function deleteClientAccount(userId) {
  const conversation = db.prepare('SELECT id FROM conversations WHERE user_id = ?').get(userId);
  if (conversation) {
    db.prepare('DELETE FROM conversation_messages WHERE conversation_id = ?').run(conversation.id);
    db.prepare('DELETE FROM conversations WHERE id = ?').run(conversation.id);
  }
  db.prepare('DELETE FROM testimonials WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM bookings WHERE user_id = ?').run(userId);
  db.prepare('UPDATE consent_records SET user_id = NULL WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
}

// Purge les réservations dont la date dépasse la durée de conservation,
// peu importe le statut (confirmée, annulée, etc.) et même si le compte
// client associé reste actif — seules les vieilles réservations sont visées,
// pas le compte lui-même.
async function purgeOldBookings() {
  try {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - BOOKING_RETENTION_DAYS);
    const cutoffStr = cutoff.toISOString().slice(0, 10);

    const result = db.prepare(`DELETE FROM bookings WHERE booking_date < ?`).run(cutoffStr);
    if (result.changes > 0) {
      logRetentionEvent('bookings_purged', `${result.changes} réservation(s) antérieure(s) au ${cutoffStr} supprimée(s).`);
      console.log(`✦ Rétention : ${result.changes} réservation(s) de plus de ${BOOKING_RETENTION_DAYS} jours purgée(s).`);
    }
  } catch (err) {
    console.error('Erreur lors de la purge des réservations :', err.message);
  }
}

// Avertit les comptes approchant la limite d'inactivité, puis supprime
// ceux qui l'ont dépassée. Le compte admin (Pierre-Olivier) est explicitement exclu,
// puisque cette politique ne vise que les comptes clients.
async function manageInactiveAccounts() {
  try {
    const warningCutoff = new Date();
    warningCutoff.setDate(warningCutoff.getDate() - INACTIVITY_WARNING_DAYS);
    const warningCutoffStr = warningCutoff.toISOString();

    const toWarn = db.prepare(`
      SELECT * FROM users
      WHERE role = 'client'
        AND last_activity_at <= ?
        AND inactivity_warning_sent_at IS NULL
    `).all(warningCutoffStr);

    for (const user of toWarn) {
      try {
        await sendInactivityWarningEmail({ name: user.name, email: user.email });
        db.prepare(`UPDATE users SET inactivity_warning_sent_at = datetime('now') WHERE id = ?`).run(user.id);
      } catch (mailErr) {
        console.error(`⚠️  Erreur envoi avertissement d'inactivité (user ${user.id}) :`, mailErr.message);
      }
    }

    const deleteCutoff = new Date();
    deleteCutoff.setDate(deleteCutoff.getDate() - INACTIVITY_DELETE_DAYS);
    const deleteCutoffStr = deleteCutoff.toISOString();

    const toDelete = db.prepare(`
      SELECT id, email FROM users
      WHERE role = 'client'
        AND last_activity_at <= ?
    `).all(deleteCutoffStr);

    for (const user of toDelete) {
      deleteClientAccount(user.id);
      logRetentionEvent('account_auto_deleted', `Compte client #${user.id} supprimé après ${INACTIVITY_DELETE_DAYS} jours d'inactivité.`);
      console.log(`✦ Rétention : compte client #${user.id} supprimé automatiquement (inactivité).`);
    }
  } catch (err) {
    console.error('Erreur lors de la gestion des comptes inactifs :', err.message);
  }
}

async function sendInactivityWarningEmail({ name, email }) {
  const fromAddress = process.env.EMAIL_FROM || 'onboarding@resend.dev';
  const html = `
    <div style="font-family:Georgia,serif;color:#352B28;max-width:480px;margin:0 auto;">
      <h2 style="color:#A87C2E;">Votre compte est inactif ✦</h2>
      <p>Bonjour ${escapeHtml(name)},</p>
      <p>Nous avons remarqué que vous ne vous êtes pas connectée à votre compte depuis un certain temps.</p>
      <p>Conformément à notre politique de conservation des renseignements personnels, votre compte et les données qui y sont associées (historique de réservations, messages) seront <strong>supprimés définitivement dans environ 13 jours</strong> si aucune activité n'est détectée.</p>
      <p>Pour conserver votre compte, il suffit de vous connecter une fois sur le site avant cette échéance.</p>
      <p style="font-size:13px;color:#8A7A74;margin-top:20px;">Si vous souhaitez plutôt supprimer votre compte dès maintenant, vous pouvez le faire vous-même depuis votre profil, dans la section « Mon compte ».</p>
      <p>Au plaisir de vous accompagner,<br>Pierre-Olivier Doucet</p>
    </div>
  `;
  await resend.emails.send({
    from: fromAddress,
    to: email,
    subject: 'Votre compte sera bientôt supprimé pour inactivité — Pierre-Olivier Doucet',
    html,
  });
}

// ============================================================
// Rappels automatiques — vérification périodique (toutes les 15 min)
// ============================================================
// Envoie un courriel de rappel aux clientes dont le rendez-vous CONFIRMÉ a
// lieu dans environ 24h. La fenêtre de tolérance (REMINDER_WINDOW_MINUTES)
// existe parce que la vérification ne tourne pas en continu, seulement à
// intervalles réguliers : sans cette marge, un rendez-vous pourrait passer
// entre deux vérifications sans jamais recevoir son rappel.
const REMINDER_CHECK_INTERVAL_MS = 15 * 60 * 1000; // toutes les 15 minutes
const REMINDER_TARGET_HOURS_BEFORE = 24;
const REMINDER_WINDOW_MINUTES = 20; // doit être > à la moitié de l'intervalle ci-dessus

async function checkAndSendReminders() {
  try {
    // Seules les réservations confirmées et pas déjà rappelées sont candidates.
    // On élargit la recherche aux deux derniers jours pour couvrir le passage
    // de minuit, puis on filtre précisément en JS avec la date/heure réelle.
    const candidates = db.prepare(`
      SELECT bookings.*, users.name as client_name, users.email as client_email
      FROM bookings
      JOIN users ON users.id = bookings.user_id
      WHERE bookings.status = 'confirme'
        AND bookings.reminder_sent_at IS NULL
        AND bookings.booking_date >= date('now')
        AND bookings.booking_date <= date('now', '+2 days')
    `).all();

    const now = Date.now();

    for (const booking of candidates) {
      const bookingMoment = new Date(`${booking.booking_date}T${booking.booking_time}:00`);
      if (Number.isNaN(bookingMoment.getTime())) continue;

      const minutesUntilBooking = (bookingMoment.getTime() - now) / (60 * 1000);
      const targetMinutes = REMINDER_TARGET_HOURS_BEFORE * 60;

      // On envoie le rappel dès que le rendez-vous entre dans la fenêtre des
      // 24h (avec une petite marge), et tant qu'il n'est pas encore passé.
      // Cette borne large (plutôt qu'une fenêtre étroite autour de 24h)
      // évite qu'un rappel soit manqué si le serveur était éteint au moment
      // précis où il aurait dû se déclencher (ex : ordinateur fermé la nuit) :
      // au prochain démarrage, le rendez-vous sera toujours détecté et rappelé,
      // pourvu qu'il reste encore à venir.
      const isWithinReminderWindow = minutesUntilBooking > 0 && minutesUntilBooking <= (targetMinutes + REMINDER_WINDOW_MINUTES);
      if (!isWithinReminderWindow) continue;

      try {
        await sendReminderEmail({
          clientName: booking.client_name,
          clientEmail: booking.client_email,
          serviceName: booking.service_name,
          bookingDateLabel: booking.booking_date_label,
          bookingTime: booking.booking_time,
        });
        db.prepare(`UPDATE bookings SET reminder_sent_at = datetime('now') WHERE id = ?`).run(booking.id);
        console.log(`✦ Rappel envoyé pour la réservation #${booking.id} (${booking.client_email})`);
      } catch (mailErr) {
        console.error(`⚠️  Erreur envoi rappel pour la réservation #${booking.id} :`, mailErr.message);
        // Pas de marquage reminder_sent_at en cas d'échec : on retentera à la prochaine vérification.
      }
    }
  } catch (err) {
    console.error('Erreur lors de la vérification des rappels :', err.message);
  }
}

// Premier passage peu après le démarrage (laisse le serveur finir de s'initialiser),
// puis vérification répétée toutes les 15 minutes tant que le serveur tourne.
setTimeout(checkAndSendReminders, 10 * 1000);
setInterval(checkAndSendReminders, REMINDER_CHECK_INTERVAL_MS);

// ============================================================
// Cycle de vie des données — vérification quotidienne
// ============================================================
// Une fois par jour suffit largement pour des durées de conservation
// comptées en mois/jours : pas besoin d'une fréquence aussi élevée que
// les rappels de rendez-vous.
const RETENTION_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // toutes les 24h
setTimeout(() => { purgeOldBookings(); manageInactiveAccounts(); }, 30 * 1000);
setInterval(() => { purgeOldBookings(); manageInactiveAccounts(); }, RETENTION_CHECK_INTERVAL_MS);

app.listen(PORT, () => {
  console.log(`\n✦ Serveur Pierre-Olivier Doucet (TEST) démarré : http://localhost:${PORT}\n`);
});
