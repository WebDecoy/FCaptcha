import { Component, signal } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { submitContact } from '../../shared/browser.js';

@Component({ selector: 'app-root', standalone: true, imports: [ReactiveFormsModule],
  template: `<main><h1>Your Angular form, server-verified.</h1>
    <p>Local demo. Messages are neither sent nor stored.</p>
    <form [formGroup]="form" (ngSubmit)="submit()">
      <label for="message">Test message</label>
      <textarea id="message" formControlName="message" maxlength="2000" required></textarea>
      <button type="submit" [disabled]="form.invalid || busy()">{{ busy() ? 'Verifying…' : 'Verify and submit' }}</button>
    </form><p role="status" aria-live="polite">{{ status() }}</p></main>`,
  styles: [`main {max-width:42rem;margin:4rem auto;font:18px system-ui;padding:1rem}textarea{display:block;width:100%;min-height:8rem;margin:1rem 0}button{padding:.8rem}`]
})
class App {
  form = new FormGroup({ message: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.maxLength(2000)] }) });
  busy = signal(false); status = signal('');
  async submit() {
    if (this.form.invalid || this.busy()) return;
    this.busy.set(true); this.status.set('');
    try { this.status.set(await submitContact(this.form.controls.message.value)); }
    catch (error) { this.status.set(error instanceof Error ? error.message : 'Unable to submit.'); }
    finally { this.busy.set(false); }
  }
}
bootstrapApplication(App).catch(console.error);
