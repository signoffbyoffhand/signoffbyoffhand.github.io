# SignOff by Offhand — prosta instrukcja

*Przygotował Marek Żak dla Offhand Hanna Nobis.*

## 1. Instalacja na tablecie / telefonie (Android i iOS)

1. Otwórz w przeglądarce adres aplikacji: **https://markulus1988.github.io/signoffbyoffhand/**
   (docelowo własna domena Offhand — patrz pkt 6).
2. **Android (Chrome):** menu ⋮ → **„Dodaj do ekranu głównego"** / „Zainstaluj aplikację".
   **iPhone/iPad (Safari):** przycisk Udostępnij (kwadrat ze strzałką) → **„Dodaj do ekranu początkowego"**.
3. Na pulpicie pojawi się ikona **SignOff**. Od tej chwili aplikacja **działa w pełni bez internetu** — kamera, podpis, PDF, wszystko.

Przy pierwszym uruchomieniu aplikacja poprosi o nazwę firmy, pierwszy projekt i PIN-y obu administratorów (Hanna Nobis i Marek Żak).

## 2. Codzienna praca w terenie

1. Dotknij swojego nazwiska i podaj PIN → **Zaloguj**.
2. Wybierz projekt z listy u góry.
3. **＋ Nowa zgoda** → wpisz dane osoby → daj jej przeczytać treść (checkboxy odblokują się po przewinięciu) → podpis palcem → zdjęcie → **Zapisz**.
4. Zgoda jest od razu zaszyfrowana i (gdy jest internet) wysłana do chmury — patrz odznaka ☁ u góry.
5. **Podpowiedzi:** na komputerze najedź myszką na przycisk; na tablecie/telefonie **przytrzymaj przycisk ok. pół sekundy** — pojawi się wyjaśnienie.

## 3. Uprawnienia

- **👑 Administrator** (Hanna Nobis, Marek Żak): wszystko — projekty, dokumenty PDF do podpisu, konta, resety PIN, chmura, cofnięcia RODO.
- **👤 Pracownik**: tylko zbieranie zgód w przydzielonych projektach i zmiana własnego PIN.
- Reset zapomnianego PIN-u: admin → Ustawienia → Konta → **🔑 Reset PIN** (stary PIN niepotrzebny).

## 4. Serwer chmury (kopie + e-maile)

Aplikacja działa bez serwera, ale serwer daje: automatyczną kopię każdej zmiany, odtwarzanie po utracie urządzenia i automatyczne e-maile z PDF-em.

**Na komputerze w biurze:** uruchom `START.bat` — konsola pokaże adres i **klucz synchronizacji**.
**W internecie (zalecane):** załóż darmowe konto na [render.com](https://render.com) → „New Web Service" → wskaż repozytorium GitHub `signoffbyoffhand` → Start Command: `node server.js` → po chwili dostajesz adres `https://signoffbyoffhand.onrender.com`. Klucz synchronizacji znajdziesz w logach serwera (zakładka Logs).

W aplikacji: Ustawienia → **☁ Chmura** → wpisz adres serwera i klucz → „Zapisz i testuj połączenie".

**E-maile automatyczne:** na serwerze utwórz plik `cloud-data/smtp.json` (wzór: `smtp.json.example`; dla Gmaila wygeneruj „hasło aplikacji" w ustawieniach konta Google). Potem w aplikacji zaznacz „Wysyłaj kopię PDF e-mailem automatycznie".

## 5. Utrata / wymiana urządzenia

Nowe urządzenie → zainstaluj aplikację (pkt 1) → przejdź szybką konfigurację z dowolnym tymczasowym PIN-em → Ustawienia → ☁ Chmura → wpisz adres + klucz → **„⬇ Przywróć z chmury"** → wybierz kopię → zaloguj się PIN-em z chwili wykonania kopii. Wraca wszystko.

(Bez serwera: Ustawienia → „⬆ Przywróć z pliku" — wskaż plik kopii zapasowej.)

## 6. Własna domena (w przyszłości)

Gdy Offhand kupi domenę (np. `signoff.offhand.pl`): w repozytorium GitHub → Settings → Pages → Custom domain → wpisz domenę i ustaw rekord CNAME u rejestratora na `markulus1988.github.io`. Adres aplikacji zmieni się na własny — bez żadnych zmian w kodzie, a zainstalowane aplikacje wystarczy dodać ponownie z nowego adresu.

## 7. Bezpieczeństwo w pigułce

- Dane na urządzeniu i w chmurze są zaszyfrowane **AES-256** — serwer i GitHub nigdy nie widzą danych osobowych.
- 5 błędnych PIN-ów = rosnąca blokada konta.
- Każda zgoda ma kartę dowodową (audit trail), sumę SHA-256 i miejsce w łańcuchu integralności — przycisk **🛡 Weryfikuj integralność** wykrywa każdą manipulację.
- Auto-wylogowanie po 5 minutach bezczynności.
- **Aplikacja sama się aktualizuje** przy dostępie do internetu — gdy pojawi się nowa wersja, na dole wyświetla pasek **„Odśwież"** (albo wchodzi automatycznie przy następnym otwarciu). Nigdy nie przerywa zbierania zgody.
