package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// gamesDir holds per-title downloaded artwork at gamesDir/<titleId>/{hero,cover,shot1..N}
// (raw image bytes, content-type sniffed at serve time). Served publicly so <img>
// works without a token.
var gamesDir = "games_media"

type gameLink struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// gameCard is the curated metadata for a Switch title, shown in the Discord-style
// game modal. Artwork (hero/cover/screenshots) lives on disk; metadata is curated here.
type gameCard struct {
	Name        string
	Tagline     string
	Description string
	Genres      []string
	Developer   string
	Publisher   string
	ReleaseDate string
	Platforms   []string
	Accent      string
	Metacritic  int
	Links       []gameLink
}

// gameAliases folds alternate title ids onto a canonical one (Splatoon 2 EU + US).
var gameAliases = map[string]string{
	"01003bc0000a0000": "0100f8f0000a2000",
	// Vus dans le store history : un build prototype de Splatoon 2 et l'ancienne
	// « Nintendo Switch Edition » de Minecraft — même jeu, donc même fiche.
	"01003bc000027000": "0100f8f0000a2000",
	"01006bd001e06000": "0100d71004694000",
}

var gamesDB = map[string]gameCard{
	"0100152000022000": {
		Name:        "Mario Kart 8 Deluxe",
		Tagline:     "Serre les virages, balance les carapaces : la course la plus folle du Royaume Champignon.",
		Description: "Mario Kart 8 Deluxe est le jeu de course de kart ultime de Nintendo, réunissant tous les personnages, circuits et modes de la version Wii U enrichis de nouveaux contenus. Affrontez vos amis en local ou en ligne à travers des courses effrénées mêlant anti-gravité, objets délirants et un mode Bataille repensé.",
		Genres:      []string{"Course", "Karting", "Arcade"},
		Developer:   "Nintendo EPD",
		Publisher:   "Nintendo",
		ReleaseDate: "28 avril 2017",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e60012",
		Metacritic:  92,
		Links: []gameLink{
			{"website", "https://mariokart8.nintendo.com/"},
			{"youtube", "https://www.youtube.com/nintendo"},
			{"x", "https://x.com/NintendoAmerica"},
			{"instagram", "https://www.instagram.com/nintendo/"},
			{"twitch", "https://www.twitch.tv/nintendo"},
			{"wikipedia", "https://fr.wikipedia.org/wiki/Mario_Kart_8_Deluxe"},
		},
	},
	"0100f8f0000a2000": {
		Name:        "Splatoon 2",
		Tagline:     "Encre, éclabousse, domine : la guerre de territoire reprend sur Switch.",
		Description: "Splatoon 2 est un jeu de tir à la troisième personne coloré où des Inklings s'affrontent en équipes de 4 pour recouvrir les arènes d'encre. Il propose des batailles en ligne compétitives, le mode coopératif Salmon Run et une aventure solo dédiée.",
		Genres:      []string{"Tir à la 3e personne", "Action", "Multijoueur en ligne"},
		Developer:   "Nintendo EPD",
		Publisher:   "Nintendo",
		ReleaseDate: "21 juillet 2017",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e73b8c",
		Metacritic:  84,
		Links: []gameLink{
			{"website", "https://splatoon.nintendo.com/"},
			{"x", "https://twitter.com/SplatoonNA"},
			{"instagram", "https://www.instagram.com/splatoon2/"},
			{"youtube", "https://www.youtube.com/c/nintendo"},
			{"wikipedia", "https://fr.wikipedia.org/wiki/Splatoon_2"},
		},
	},
	"01006a800016e000": {
		Name:        "Super Smash Bros. Ultimate",
		Tagline:     "Ils sont tous là. Le crossover ultime de la baston Nintendo.",
		Description: "Le jeu de combat crossover ultime de Nintendo réunissant tous les combattants de l'histoire de la série ainsi qu'une multitude d'invités issus d'autres univers. Affrontez jusqu'à huit joueurs sur des dizaines de stages, en local comme en ligne.",
		Genres:      []string{"Combat", "Action", "Arcade"},
		Developer:   "Bandai Namco Studios, Sora Ltd.",
		Publisher:   "Nintendo",
		ReleaseDate: "7 décembre 2018",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#a8112a",
		Metacritic:  93,
		Links: []gameLink{
			{"website", "https://www.smashbros.com/fr_FR/"},
			{"x", "https://x.com/NintendoVS"},
			{"youtube", "https://www.youtube.com/@Nintendo"},
			{"instagram", "https://www.instagram.com/nintendo/"},
			{"wikipedia", "https://fr.wikipedia.org/wiki/Super_Smash_Bros._Ultimate"},
		},
	},
	"0100c2500fc20000": {
		Name:        "Splatoon 3",
		Tagline:     "Encre, chaos et Turf War : bienvenue à Splatsville, la cité du chaos.",
		Description: "Splatoon 3 est un jeu de tir à la troisième personne coloré où Inklings et Octalings s'affrontent en recouvrant l'arène d'encre lors de batailles de Guerre de Territoire en 4 contre 4. Il propose aussi un mode solo, le coopératif Salmon Run et des Festivals en ligne réguliers.",
		Genres:      []string{"Tir à la 3e personne", "Action", "Multijoueur en ligne"},
		Developer:   "Nintendo EPD",
		Publisher:   "Nintendo",
		ReleaseDate: "9 septembre 2022",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#eab308",
		Metacritic:  84,
		Links: []gameLink{
			{"website", "https://splatoon.nintendo.com/"},
			{"x", "https://x.com/SplatoonNA"},
			{"youtube", "https://www.youtube.com/@Nintendo"},
			{"wikipedia", "https://fr.wikipedia.org/wiki/Splatoon_3"},
		},
	},

	// ---------------------------------------------------------------------------
	// Titres non-Nextendo les plus joués par les comptes (relevé sur le store
	// history : classement par nombre de comptes distincts). Ils n'ont pas de
	// visuels dans games_media/ : la fiche retombe alors sur l'icône du jeu
	// remontée par l'émulateur, et les lignes sans donnée se masquent d'elles-mêmes.
	// Metacritic/date ne sont renseignés que lorsqu'ils sont sûrs.
	// ---------------------------------------------------------------------------
	"0100965017338000": {
		Name:        "Super Mario Party Jamboree",
		Tagline:     "Sept plateaux, 110 mini-jeux : la fête ne s'arrête jamais.",
		Description: "Le plus copieux des Mario Party : sept plateaux, plus de 110 mini-jeux et une poignée de modes annexes pour jouer jusqu'à quatre en local comme en ligne. Chaque partie mêle stratégie de parcours, objets vicieux et coups de dé décisifs.",
		Genres:      []string{"Party game", "Mini-jeux", "Multijoueur"},
		Developer:   "NDcube", Publisher: "Nintendo",
		ReleaseDate: "17 octobre 2024",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#f5b301", Metacritic: 78,
	},
	"01009b90006dc000": {
		Name:        "Super Mario Maker 2",
		Tagline:     "Construisez le niveau de vos rêves — ou le cauchemar des autres.",
		Description: "L'atelier de création de niveaux Mario, enrichi de pentes, de nouveaux thèmes et d'un mode Histoire de plus de cent niveaux signés Nintendo. Publiez vos créations et affrontez celles du monde entier.",
		Genres:      []string{"Plateforme", "Création de niveaux"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "28 juin 2019",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e8a33d", Metacritic: 88,
	},
	"010051f0207b2000": {
		Name:        "Tomodachi Life: Living the Dream",
		Tagline:     "Vos Mii vivent leur vie. Vous regardez, un peu inquiet.",
		Description: "Une simulation de vie loufoque où vos Mii habitent une île, se lient d'amitié, se disputent, tombent amoureux et font des rêves absurdes. Vous n'êtes pas vraiment aux commandes : vous observez, vous nourrissez, vous provoquez le chaos.",
		Genres:      []string{"Simulation de vie", "Bac à sable"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "2026",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#f9c22e",
	},
	"0100000000010000": {
		Name:        "Super Mario Odyssey",
		Tagline:     "Une casquette, un chapeau vivant, et le monde entier à capturer.",
		Description: "Mario parcourt des royaumes très différents à bord de l'Odyssey pour arracher Peach à Bowser. Grâce à Cappy, il prend le contrôle de créatures et d'objets, ouvrant un terrain de jeu d'une inventivité rare.",
		Genres:      []string{"Plateforme 3D", "Aventure"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "27 octobre 2017",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#d92b2b", Metacritic: 97,
	},
	"0100f2c0115b6000": {
		Name:        "The Legend of Zelda: Tears of the Kingdom",
		Tagline:     "Le ciel, la surface, les profondeurs — et tout ce que vous pouvez bricoler.",
		Description: "La suite de Breath of the Wild étend Hyrule vers les îles célestes et un vaste monde souterrain. Les pouvoirs d'amalgame et d'emprise transforment chaque objet en pièce de machine : presque tous les problèmes ont mille solutions.",
		Genres:      []string{"Action-aventure", "Monde ouvert"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "12 mai 2023",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#c9a227", Metacritic: 96,
	},
	"0100f43008c44000": {
		Name:        "Pokémon Legends: Z-A",
		Tagline:     "Illumis se réinvente — et les combats passent en temps réel.",
		Description: "Un opus Légendes entièrement situé dans la ville d'Illumis, en pleine refonte urbaine. Les affrontements abandonnent le tour par tour strict au profit de combats en temps réel où le placement compte autant que le choix des attaques.",
		Genres:      []string{"RPG", "Aventure"},
		Developer:   "Game Freak", Publisher: "Nintendo, The Pokémon Company",
		ReleaseDate: "16 octobre 2025",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#4a90d9",
	},
	"010015100b514000": {
		Name:        "Super Mario Bros. Wonder",
		Tagline:     "Une fleur prodige, et le niveau part complètement en vrille.",
		Description: "Le retour du Mario en 2D, dans le royaume des Fleurs. Les fleurs prodiges tordent les règles en pleine partie : tuyaux qui ondulent, hordes de Piranha chantants, perspectives qui basculent. Jusqu'à quatre joueurs en local.",
		Genres:      []string{"Plateforme 2D", "Aventure"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "20 octobre 2023",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e8453c", Metacritic: 92,
	},
	"01006fe013472000": {
		Name:        "Mario Party Superstars",
		Tagline:     "Cinq plateaux cultes de la N64 et cent mini-jeux, remis à neuf.",
		Description: "Une compilation best-of : cinq plateaux emblématiques de l'ère Nintendo 64 et une centaine de mini-jeux tirés de toute la série, rejouables en ligne. Les règles reviennent à la formule classique, sans voiture commune.",
		Genres:      []string{"Party game", "Mini-jeux", "Multijoueur"},
		Developer:   "NDcube", Publisher: "Nintendo",
		ReleaseDate: "29 octobre 2021",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#2e7fd4", Metacritic: 80,
	},
	"010019401051c000": {
		Name:        "Mario Strikers: Battle League",
		Tagline:     "Du football sans arbitre, avec des carapaces et des tacles.",
		Description: "Un football arcade à cinq contre cinq où les coups bas sont encouragés : tacles, objets et frappes surpuissantes. L'équipement modifie les statistiques des personnages, et le mode en ligne repose sur des clubs gérés par les joueurs.",
		Genres:      []string{"Sport", "Arcade", "Multijoueur"},
		Developer:   "Next Level Games", Publisher: "Nintendo",
		ReleaseDate: "10 juin 2022",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#2fae5f", Metacritic: 71,
	},
	"010028600ebda000": {
		Name:        "Super Mario 3D World + Bowser's Fury",
		Tagline:     "Le costume de chat, et un Bowser gigantesque en pleine colère.",
		Description: "Le portage du Mario 3D de la Wii U, jouable à quatre, accompagné de Bowser's Fury : une aventure inédite en monde ouvert où Mario affronte un Bowser colossal qui resurgit périodiquement.",
		Genres:      []string{"Plateforme 3D", "Aventure"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "12 février 2021",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#37a3d6", Metacritic: 89,
	},
	"0100ea80032ea000": {
		Name:        "New Super Mario Bros. U Deluxe",
		Tagline:     "Le Mario 2D de la Wii U, avec Toadette et la super couronne.",
		Description: "New Super Mario Bros. U et son extension Luigi U réunis, avec deux personnages plus accessibles : Toadette, qui peut se transformer grâce à la super couronne, et Carottin. Jusqu'à quatre joueurs en simultané.",
		Genres:      []string{"Plateforme 2D", "Aventure"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "11 janvier 2019",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#d33a2c", Metacritic: 79,
	},
	"0100d71004694000": {
		Name:        "Minecraft",
		Tagline:     "Creusez, bâtissez, survivez. Puis recommencez en plus grand.",
		Description: "Le bac à sable le plus vendu de l'histoire : un monde de blocs généré à l'infini où l'on récolte, fabrique et construit, seul ou à plusieurs. Mode Survie pour l'aventure, mode Créatif pour bâtir sans contrainte.",
		Genres:      []string{"Bac à sable", "Survie", "Construction"},
		Developer:   "Mojang Studios", Publisher: "Mojang Studios",
		ReleaseDate: "21 juin 2018",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#5d8c3f",
	},
	"0100abf008968000": {
		Name:        "Pokémon Sword",
		Tagline:     "Galar, les arènes et les Pokémon Dynamax géants.",
		Description: "Le premier Pokémon principal sur Switch, situé dans la région de Galar inspirée du Royaume-Uni. Les combats d'arène se déroulent en stade devant une foule, avec le phénomène Dynamax qui fait enfler les Pokémon le temps de trois tours.",
		Genres:      []string{"RPG", "Aventure"},
		Developer:   "Game Freak", Publisher: "Nintendo, The Pokémon Company",
		ReleaseDate: "15 novembre 2019",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#2f7fc1", Metacritic: 80,
	},
	"01001f5010dfa000": {
		Name:        "Pokémon Legends: Arceus",
		Tagline:     "Hisui, avant les dresseurs : on lance la Ball soi-même.",
		Description: "Un Pokémon d'action situé dans le Hisui d'autrefois, l'ancienne région de Sinnoh. On observe, on se faufile et on lance ses Balls en temps réel dans de vastes zones ouvertes, pour constituer le tout premier Pokédex.",
		Genres:      []string{"RPG", "Action-aventure"},
		Developer:   "Game Freak", Publisher: "Nintendo, The Pokémon Company",
		ReleaseDate: "28 janvier 2022",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#c6a15b", Metacritic: 83,
	},
	"010003f003a34000": {
		Name:        "Pokémon : Let's Go, Pikachu!",
		Tagline:     "Kanto revisité, avec Pikachu sur l'épaule.",
		Description: "Une relecture de Pokémon Jaune pensée pour les nouveaux venus : la capture reprend le geste de Pokémon GO, Pikachu vous suit partout, et un second joueur peut rejoindre l'aventure à tout moment.",
		Genres:      []string{"RPG", "Aventure"},
		Developer:   "Game Freak", Publisher: "Nintendo, The Pokémon Company",
		ReleaseDate: "16 novembre 2018",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#f2c02e", Metacritic: 79,
	},
	"0100f9f00c696000": {
		Name:        "Crash Team Racing Nitro-Fueled",
		Tagline:     "Le kart le plus exigeant du lot — maîtrisez le boost ou perdez.",
		Description: "Le remake intégral de Crash Team Racing, avec tous les circuits de l'original et de Nitro Kart. Le pilotage repose sur un enchaînement de dérapages et de boosts au timing serré, qui récompense la maîtrise plutôt que la chance.",
		Genres:      []string{"Course", "Karting", "Arcade"},
		Developer:   "Beenox", Publisher: "Activision",
		ReleaseDate: "21 juin 2019",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e8722a", Metacritic: 82,
	},
	"0100dca0064a6000": {
		Name:        "Luigi's Mansion 3",
		Tagline:     "Un hôtel hanté, un aspirateur, et un Luigi terrifié.",
		Description: "Luigi explore étage par étage un hôtel hanté pour délivrer ses amis. Le Ectoblast 3000 aspire, projette et déploie Gluigi, un double de gelée qui se faufile là où Luigi ne passe pas — le cœur des énigmes du jeu.",
		Genres:      []string{"Action-aventure", "Puzzle"},
		Developer:   "Next Level Games", Publisher: "Nintendo",
		ReleaseDate: "31 octobre 2019",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#4caf50", Metacritic: 86,
	},
	"01007ef00011e000": {
		Name:        "The Legend of Zelda: Breath of the Wild",
		Tagline:     "Grimpez n'importe où. Vraiment n'importe où.",
		Description: "Le Zelda qui a redéfini le monde ouvert : un Hyrule dévasté que l'on traverse librement, sans itinéraire imposé. Escalade, planeur, physique et météo forment un système cohérent où l'expérimentation est presque toujours récompensée.",
		Genres:      []string{"Action-aventure", "Monde ouvert"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "3 mars 2017",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#2e9bb5", Metacritic: 97,
	},
	"01004d300c5ae000": {
		Name:        "Kirby and the Forgotten Land",
		Tagline:     "Kirby passe à la 3D — et avale carrément une voiture.",
		Description: "La première aventure principale de Kirby en 3D, dans un monde envahi par la nature. Le Transformorphe lui permet d'engloutir des objets entiers — voiture, distributeur, escalier — pour en tirer des capacités inattendues.",
		Genres:      []string{"Plateforme 3D", "Action"},
		Developer:   "HAL Laboratory", Publisher: "Nintendo",
		ReleaseDate: "25 mars 2022",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#f28aa8", Metacritic: 85,
	},
	"01006d0017f7a000": {
		Name:        "Mario & Luigi: Brothership",
		Tagline:     "Deux frères, un archipel à recoller.",
		Description: "Le retour du RPG Mario & Luigi : les deux frères naviguent entre les îles d'un archipel à reconnecter. Les combats gardent le timing d'action de la série — chaque coup porté ou esquivé dépend d'une pression de bouton bien placée.",
		Genres:      []string{"RPG", "Aventure"},
		Developer:   "Acquire", Publisher: "Nintendo",
		ReleaseDate: "7 novembre 2024",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#2ea3a3",
	},
	"01006f8002326000": {
		Name:        "Animal Crossing: New Horizons",
		Tagline:     "Une île déserte, et tout le temps du monde.",
		Description: "Vous débarquez sur une île déserte et l'aménagez à votre rythme, jour après jour, au fil des saisons réelles. Pêche, insectes, décoration, terraformation : aucun objectif imposé, seulement ce que vous décidez d'en faire.",
		Genres:      []string{"Simulation de vie", "Bac à sable"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "20 mars 2020",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#6dc6a5", Metacritic: 90,
	},
	"0100a250097f0000": {
		Name:        "DRAGON BALL FighterZ",
		Tagline:     "Trois contre trois, et une claque visuelle à chaque combo.",
		Description: "Un jeu de combat en équipes de trois signé Arc System Works, dont le rendu 3D imite à la perfection l'animation de la série. Accessible en surface, redoutablement technique en profondeur, avec un fort accent compétitif.",
		Genres:      []string{"Combat", "Multijoueur en ligne"},
		Developer:   "Arc System Works", Publisher: "Bandai Namco Entertainment",
		ReleaseDate: "28 septembre 2018",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e8642a", Metacritic: 85,
	},
	"0100f4c009322000": {
		Name:        "Pikmin 3 Deluxe",
		Tagline:     "Commandez une armée minuscule, et ne perdez personne.",
		Description: "Trois explorateurs échoués sur une planète inconnue dirigent des Pikmin pour récolter des fruits et survivre. Chaque journée est une énigme logistique : répartir ses troupes, anticiper les prédateurs, tout ramener avant la nuit.",
		Genres:      []string{"Stratégie", "Aventure"},
		Developer:   "Nintendo EPD", Publisher: "Nintendo",
		ReleaseDate: "30 octobre 2020",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#7bb241", Metacritic: 85,
	},
	"0100770008dd8000": {
		Name:        "MONSTER HUNTER GENERATIONS ULTIMATE",
		Tagline:     "Des centaines d'heures de chasse, et un plafond très haut.",
		Description: "L'épisode le plus généreux en contenu de la série avant Monster Hunter World : quatorze styles de chasse, des monstres tirés de toute l'histoire de la licence, et une coopération à quatre qui récompense la préparation.",
		Genres:      []string{"Action-RPG", "Coopératif"},
		Developer:   "Capcom", Publisher: "Capcom",
		ReleaseDate: "28 août 2018",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#8a6b3f", Metacritic: 85,
	},
	"01008f6008c5e000": {
		Name:        "Pokémon Violet",
		Tagline:     "Paldea en monde ouvert : trois aventures, dans l'ordre que vous voulez.",
		Description: "Le premier Pokémon principal entièrement en monde ouvert, dans la région de Paldea. Trois scénarios se déroulent en parallèle — arènes, chefs d'équipe, Pokémon dominants — et vous les abordez dans l'ordre de votre choix.",
		Genres:      []string{"RPG", "Monde ouvert"},
		Developer:   "Game Freak", Publisher: "Nintendo, The Pokémon Company",
		ReleaseDate: "18 novembre 2022",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#8b5fbf", Metacritic: 72,
	},
	"01006560184e6000": {
		Name:        "Mortal Kombat 1",
		Tagline:     "Un univers redémarré, et des Kameo en renfort.",
		Description: "Redémarrage de la saga après Mortal Kombat 11 : Liu Kang a reforgé la réalité. Le système de Kameo ajoute un second combattant en soutien, appelable en plein combo, qui redéfinit les enchaînements.",
		Genres:      []string{"Combat", "Multijoueur en ligne"},
		Developer:   "NetherRealm Studios", Publisher: "Warner Bros. Games",
		ReleaseDate: "19 septembre 2023",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#b3202a",
	},
	// Rééditions Switch récentes : le contenu du jeu est connu, mais la date de sortie
	// et le score de cette édition ne le sont pas de façon sûre — on les laisse vides
	// plutôt que de les inventer (les lignes correspondantes se masquent d'elles-mêmes).
	"010099c022b96000": {
		Name:        "Super Mario Galaxy",
		Tagline:     "De planète en planète, la gravité devient un terrain de jeu.",
		Description: "Mario saute de planétoïde en planétoïde, chacun avec sa propre gravité : le sol se courbe, le haut et le bas changent de sens. Une bande-son orchestrale et un sens du vertige qui ont marqué la plateforme 3D.",
		Genres:      []string{"Plateforme 3D", "Aventure"},
		Developer:   "Nintendo EAD", Publisher: "Nintendo",
		Platforms: []string{"Nintendo Switch"},
		Accent:    "#3d6fc4",
	},
	"0100fd8022daa000": {
		Name:        "Super Mario Galaxy 2",
		Tagline:     "La même magie cosmique, avec Yoshi en renfort.",
		Description: "La suite directe de Super Mario Galaxy : de nouvelles galaxies, un rythme plus soutenu et Yoshi comme monture, capable de gober les ennemis et d'atteindre des zones inaccessibles à Mario seul.",
		Genres:      []string{"Plateforme 3D", "Aventure"},
		Developer:   "Nintendo EAD", Publisher: "Nintendo",
		Platforms: []string{"Nintendo Switch"},
		Accent:    "#2f9b57",
	},
	"0100d9f01d474000": {
		Name:        "Rhythm Heaven Groove",
		Tagline:     "Un bouton, le bon timing. C'est tout — et c'est redoutable.",
		Description: "Un jeu de rythme fait de courtes saynètes absurdes, où tout repose sur l'écoute plutôt que sur des repères visuels. Chaque tableau introduit sa propre règle et se juge à la précision du geste.",
		Genres:      []string{"Rythme", "Musical"},
		Publisher:   "Nintendo",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e8598b",
	},
	"01005ff002e2a000": {
		Name:        "Rayman Legends: Definitive Edition",
		Tagline:     "Le plateformer 2D le plus élégant de sa génération.",
		Description: "Un jeu de plateforme 2D à l'animation dessinée à la main, réputé pour la précision de son maniement et ses niveaux musicaux réglés à la note près. Cette édition ajoute des contenus et des défis propres à la Switch.",
		Genres:      []string{"Plateforme 2D", "Aventure"},
		Developer:   "Ubisoft Montpellier", Publisher: "Ubisoft",
		ReleaseDate: "12 septembre 2017",
		Platforms:   []string{"Nintendo Switch"},
		Accent:      "#e0662c", Metacritic: 86,
	},
}

var reShot = regexp.MustCompile(`^shot[1-9][0-9]?$`)

func canonTitleID(tid string) string {
	tid = strings.ToLower(strings.TrimSpace(tid))
	if a, ok := gameAliases[tid]; ok {
		return a
	}
	return tid
}

func gameMediaExists(tid, kind string) bool {
	st, err := os.Stat(filepath.Join(gamesDir, tid, kind))
	return err == nil && !st.IsDir() && st.Size() > 0
}

// gameInfo: GET ?title_id=X&name=Y returns the curated card + artwork/screenshot URLs.
func (s *server) gameInfo(w http.ResponseWriter, r *http.Request) {
	tid := canonTitleID(r.URL.Query().Get("title_id"))
	out := map[string]any{"title_id": tid}
	if card, ok := gamesDB[tid]; ok {
		out["name"] = card.Name
		out["tagline"] = card.Tagline
		out["description"] = card.Description
		out["genres"] = card.Genres
		out["developer"] = card.Developer
		out["publisher"] = card.Publisher
		out["release_date"] = card.ReleaseDate
		out["platforms"] = card.Platforms
		out["accent"] = card.Accent
		out["metacritic"] = card.Metacritic
		out["links"] = card.Links
	} else {
		out["name"] = strings.TrimSpace(r.URL.Query().Get("name"))
	}
	if reTitleID.MatchString(tid) {
		if gameMediaExists(tid, "hero") {
			out["hero"] = "/api/gamemedia/" + tid + "/hero"
		}
		if gameMediaExists(tid, "cover") {
			out["cover"] = "/api/gamemedia/" + tid + "/cover"
		}
		shots := []string{}
		for i := 1; i <= 12; i++ {
			k := "shot" + itoa(i)
			if gameMediaExists(tid, k) {
				shots = append(shots, "/api/gamemedia/"+tid+"/"+k)
			}
		}
		out["screenshots"] = shots
	}
	writeJSON(w, http.StatusOK, out)
}

// gameMedia: GET /api/gamemedia/<titleId>/<hero|cover|shotN> streams the image.
func (s *server) gameMedia(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/gamemedia/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	tid := canonTitleID(parts[0])
	kind := parts[1]
	if !(kind == "hero" || kind == "cover" || reShot.MatchString(kind)) || !reTitleID.MatchString(tid) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(gamesDir, tid, kind))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", http.DetectContentType(buf[:n]))
	w.Header().Set("Cache-Control", "public, max-age=604800")
	_, _ = io.Copy(w, f)
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
