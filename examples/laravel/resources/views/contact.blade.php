<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>FCaptcha + Laravel</title>
</head>
<body>
<main>
    <h1>FCaptcha + Laravel</h1>
    <form method="post" action="{{ route('contact.store') }}">
        @csrf
        <label for="message">Sample message</label>
        <textarea id="message" name="message" maxlength="2000" required>{{ old('message') }}</textarea>
        @error('message') <p role="alert">{{ $message }}</p> @enderror
        @error('fcaptcha_token') <p role="alert">{{ $message }}</p> @enderror
        <div
            data-fcaptcha="{{ config('services.fcaptcha.site_key') }}"
            data-endpoint="{{ config('services.fcaptcha.origin') }}"
            data-action="contact"
        ></div>
        <button type="submit">Send sample</button>
    </form>
</main>
<script src="{{ config('services.fcaptcha.origin') }}/fcaptcha.js"></script>
</body>
</html>
