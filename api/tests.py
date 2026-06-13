"""
Testy bezpieczeństwa PasswordManager
=====================================
Uruchomienie:
    source venv/bin/activate
    python manage.py test api.tests -v 2

Oczekiwane wyniki zależą od aktywnego brancha:

    main          → UserEnumeration: 2 FAIL  | BruteForce: SKIP | Auth/IDOR: PASS
    salty_fix     → UserEnumeration: PASS    | BruteForce: SKIP | Auth/IDOR: PASS
    rate_limiting → UserEnumeration: 2 FAIL  | BruteForce: PASS | Auth/IDOR: PASS
    (po merge obu)→ wszystkie PASS
"""
import unittest
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken
from . import models as _m
from .models import CustomUser, PasswordItem

# Testy brute-force wymagają modelu LoginAttempt z brancha rate_limiting
HAS_RATE_LIMITING = hasattr(_m, 'LoginAttempt')


class UserEnumerationTests(TestCase):
    """
    Weryfikuje czy /api/get-salt/ ujawnia istnienie konta po kodzie odpowiedzi.
    Podatność: main zwraca 404 dla nieistniejącego emaila → atakujący może
    sprawdzić tysiące adresów i dowiedzieć się które konta istnieją.
    Naprawa: branch salty_fix — zawsze HTTP 200, deterministyczna fałszywa sól.
    """

    def setUp(self):
        CustomUser.objects.create_user(
            email='istniejacy@test.pl',
            salt='dGVzdHNhbHQ=',
            auth_key_hash='dGVzdGhhc2g='
        )

    def test_istniejacy_uzytkownik_zwraca_200(self):
        r = self.client.post('/api/get-salt/',
            {'email': 'istniejacy@test.pl'},
            content_type='application/json')
        self.assertEqual(r.status_code, 200)

    def test_nieistniejacy_uzytkownik_zwraca_200(self):
        # FAIL na main (zwraca 404) — zdradza że konto nie istnieje
        r = self.client.post('/api/get-salt/',
            {'email': 'nieistniejacy@test.pl'},
            content_type='application/json')
        self.assertEqual(r.status_code, 200,
            "PODATNOSC: endpoint zwraca 404 dla nieistniejacych emaili — "
            "umozliwia enumeracje uzytkownikow. Merge branch salty_fix.")

    def test_fake_sol_jest_deterministyczna(self):
        # Ten sam nieistniejący email musi zawsze dawać tę samą sól
        # (gdyby była losowa, atakujący wykryłby różnicę między dwoma wywołaniami)
        r1 = self.client.post('/api/get-salt/',
            {'email': 'ghost@test.pl'},
            content_type='application/json')
        r2 = self.client.post('/api/get-salt/',
            {'email': 'ghost@test.pl'},
            content_type='application/json')
        self.assertEqual(r1.json().get('salt'), r2.json().get('salt'),
            "PODATNOSC: falszywa sol jest losowa — atakujacy wykryje "
            "ze konto nie istnieje porownujac dwie odpowiedzi.")


@unittest.skipUnless(HAS_RATE_LIMITING, "SKIP: brak modelu LoginAttempt — merge branch rate_limiting")
class BruteForceTests(TestCase):
    """
    Weryfikuje ochronę przed atakiem brute-force na /api/login/.
    Bez rate limitingu atakujący może wysłać nieograniczoną liczbę żądań
    i metodą słownikową złamać auth_key_hash.
    Naprawa: branch rate_limiting — blokada IP po 5 nieudanych próbach.
    """

    def setUp(self):
        CustomUser.objects.create_user(
            email='cel@test.pl',
            salt='dGVzdHNhbHQ=',
            auth_key_hash='poprawnyHash123'
        )

    def _login(self, auth_key_hash='zlyHash'):
        return self.client.post('/api/login/',
            {'email': 'cel@test.pl', 'auth_key_hash': auth_key_hash},
            content_type='application/json')

    def test_poprawne_logowanie_dziala_przed_limitem(self):
        r = self._login('poprawnyHash123')
        self.assertEqual(r.status_code, 200)

    def test_blokada_po_5_blednych_probach(self):
        for _ in range(5):
            self._login('zlyHash')
        r = self._login('zlyHash')
        self.assertEqual(r.status_code, 429,
            "PODATNOSC: brak rate limitingu — mozliwy atak brute-force.")

    def test_poprawne_haslo_blokowane_gdy_ip_zablokowane(self):
        # Nawet jeśli atakujący zgadnie hasło, IP jest już zablokowane
        for _ in range(5):
            self._login('zlyHash')
        r = self._login('poprawnyHash123')
        self.assertEqual(r.status_code, 429)

    def test_blokada_po_ataku_z_roznych_ip_na_ten_sam_email(self):
        # Botnet z różnych IP atakujący jedno konto — blokada przez licznik emaila
        for i in range(5):
            self.client.post('/api/login/',
                {'email': 'cel@test.pl', 'auth_key_hash': 'zlyHash'},
                content_type='application/json',
                REMOTE_ADDR=f'10.0.0.{i+1}')
        r = self.client.post('/api/login/',
            {'email': 'cel@test.pl', 'auth_key_hash': 'zlyHash'},
            content_type='application/json',
            REMOTE_ADDR='10.0.0.99')
        self.assertEqual(r.status_code, 429)

    def test_blokada_jednego_ip_atakujacego_rozne_emaile(self):
        # Jeden IP próbuje różnych emaili — blokada przez licznik IP
        for i in range(5):
            self.client.post('/api/login/',
                {'email': f'ofiara{i}@test.pl', 'auth_key_hash': 'zlyHash'},
                content_type='application/json',
                REMOTE_ADDR='5.5.5.5')
        r = self.client.post('/api/login/',
            {'email': 'kolejna@test.pl', 'auth_key_hash': 'zlyHash'},
            content_type='application/json',
            REMOTE_ADDR='5.5.5.5')
        self.assertEqual(r.status_code, 429)


class AuthenticationTests(TestCase):
    """
    Weryfikuje czy endpointy wymagają tokenu JWT.
    Powinny przechodzić na wszystkich branchach.
    """

    def test_lista_hasel_wymaga_tokenu(self):
        r = self.client.get('/api/passwords/')
        self.assertEqual(r.status_code, 401)

    def test_szczegoly_hasla_wymagaja_tokenu(self):
        r = self.client.get('/api/passwords/1/')
        self.assertEqual(r.status_code, 401)

    def test_usuwanie_hasla_wymaga_tokenu(self):
        r = self.client.delete('/api/passwords/1/')
        self.assertEqual(r.status_code, 401)

    def test_edycja_hasla_wymaga_tokenu(self):
        r = self.client.put('/api/passwords/1/',
            {'url': 'x', 'iv': 'x', 'ciphertext': 'x', 'tag': 'x'},
            content_type='application/json')
        self.assertEqual(r.status_code, 401)


class IDORTests(TestCase):
    """
    Testuje Insecure Direct Object Reference — czy użytkownik A może
    odczytać lub usunąć hasła użytkownika B podając jego ID w URL.
    Powinny przechodzić na wszystkich branchach (zabezpieczenie istnieje od początku).
    """

    def setUp(self):
        self.user_a = CustomUser.objects.create_user(
            email='a@test.pl', salt='saltA', auth_key_hash='hashA'
        )
        self.user_b = CustomUser.objects.create_user(
            email='b@test.pl', salt='saltB', auth_key_hash='hashB'
        )
        self.wpis_b = PasswordItem.objects.create(
            user=self.user_b,
            url='https://przyklad.pl',
            iv='testIV123456',
            ciphertext='zaszyfrowaneDane',
            tag='testTag'
        )

    def _token(self, user):
        return str(RefreshToken.for_user(user).access_token)

    def test_user_a_nie_widzi_hasel_user_b(self):
        r = self.client.get(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_a)}'
        )
        self.assertEqual(r.status_code, 404)

    def test_user_a_nie_moze_usunac_hasel_user_b(self):
        r = self.client.delete(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_a)}'
        )
        self.assertEqual(r.status_code, 404)

    def test_user_b_widzi_wlasne_hasla(self):
        r = self.client.get(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_b)}'
        )
        self.assertEqual(r.status_code, 200)

    def test_user_b_moze_usunac_wlasne_haslo(self):
        r = self.client.delete(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_b)}'
        )
        self.assertEqual(r.status_code, 204)
