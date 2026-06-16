# SignOff — kopia w chmurze na Firebase (Storage)

Cel: trwała, darmowa kopia zaszyfrowanych zgód w UE — jak w aplikacji urlopowej, ale dane są szyfrowane end-to-end, więc Firebase **nigdy nie widzi treści**.

Architektura: aplikacja loguje się do Firebase (e-mail+hasło konta technicznego), a po każdej zmianie wysyła **jeden zaszyfrowany plik** do **Firebase Storage** (`signoff/dev-<urządzenie>.json`). Bez SDK — czystym REST-em, więc działa też offline (synchronizuje, gdy jest sieć).

## Co musi zrobić Marek raz (~5 min) — tylko Ty masz do tego dostęp

1. **Projekt.** [console.firebase.google.com](https://console.firebase.google.com) → zaloguj `markulus1988@gmail.com` → „Dodaj projekt" → nazwa `signoff-offhand` → utwórz (Google Analytics niepotrzebne).

2. **Aplikacja webowa.** W projekcie: ikona `</>` („Dodaj aplikację" web) → nazwa `signoff` → zarejestruj. Pokaże się `firebaseConfig` — **skopiuj z niego `apiKey`, `projectId` i `storageBucket`** (to dane jawne, można je podać).

3. **Logowanie e-mailem.** Menu **Authentication** → „Rozpocznij" → karta „Sign-in method" → włącz **Adres e-mail/hasło**. Potem karta „Users" → „Dodaj użytkownika" → wpisz e-mail techniczny (np. `signoff@offhand…` albo dowolny) + hasło. **Zapamiętaj ten e-mail i hasło** — wpiszesz je w aplikacji.

4. **Storage.** Menu **Storage** → „Rozpocznij" → wybierz lokalizację **europe-west** (UE) → dalej. Następnie karta **Rules** → wklej poniższe i „Opublikuj":

```
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /signoff/{file=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```
(czyli: tylko zalogowany — przez nasze konto techniczne — może czytać/pisać; a i tak wszystko jest zaszyfrowane).

## Co podajesz mnie / wpisujesz w aplikacji
- `apiKey`
- `projectId`
- `storageBucket` (np. `signoff-offhand.appspot.com`)
- e-mail i hasło konta technicznego z punktu 3

W aplikacji: Ustawienia → **☁ Chmura (Firebase)** → wklej powyższe → „Zapisz i testuj". Od tej chwili każda zgoda ląduje w trwałej kopii, a na nowym urządzeniu „Przywróć z chmury" odtwarza wszystko.
