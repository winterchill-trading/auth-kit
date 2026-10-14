/* Argon2id through the reference implementation (libargon2).

   The inputs are copied out of the OCaml heap so the runtime lock can be released for
   the derivation: a hash at the default costs takes 15-20 ms, and other threads (an
   Async scheduler running In_thread.run) keep going meanwhile. */

#include <stdlib.h>
#include <string.h>

#include <argon2.h>

#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/signals.h>

static uint8_t *copy_string(value s, size_t *len) {
  *len = caml_string_length(s);
  uint8_t *p = malloc(*len ? *len : 1);
  if (p == NULL) caml_raise_out_of_memory();
  memcpy(p, String_val(s), *len);
  return p;
}

static void wipe_free(uint8_t *p, size_t len) {
  /* volatile so the compiler cannot drop the wipe of a buffer about to be freed */
  volatile uint8_t *v = p;
  for (size_t i = 0; i < len; i++) v[i] = 0;
  free(p);
}

/* costs: an OCaml record { iterations; memory_kib; parallelism; hash_length } */
CAMLprim value auth_kit_argon2id_raw(value v_pwd, value v_salt, value v_secret,
                                     value v_ad, value v_costs) {
  CAMLparam5(v_pwd, v_salt, v_secret, v_ad, v_costs);
  CAMLlocal1(v_out);
  size_t pwdlen, saltlen, secretlen, adlen;
  uint32_t t_cost = (uint32_t)Long_val(Field(v_costs, 0));
  uint32_t m_cost = (uint32_t)Long_val(Field(v_costs, 1));
  uint32_t lanes = (uint32_t)Long_val(Field(v_costs, 2));
  size_t outlen = (size_t)Long_val(Field(v_costs, 3));
  uint8_t *pwd = copy_string(v_pwd, &pwdlen);
  uint8_t *salt = copy_string(v_salt, &saltlen);
  uint8_t *secret = copy_string(v_secret, &secretlen);
  uint8_t *ad = copy_string(v_ad, &adlen);
  uint8_t *out = malloc(outlen ? outlen : 1);
  if (out == NULL) caml_raise_out_of_memory();

  argon2_context ctx;
  memset(&ctx, 0, sizeof ctx);
  ctx.out = out;
  ctx.outlen = (uint32_t)outlen;
  ctx.pwd = pwd;
  ctx.pwdlen = (uint32_t)pwdlen;
  ctx.salt = salt;
  ctx.saltlen = (uint32_t)saltlen;
  ctx.secret = secretlen ? secret : NULL;
  ctx.secretlen = (uint32_t)secretlen;
  ctx.ad = adlen ? ad : NULL;
  ctx.adlen = (uint32_t)adlen;
  ctx.t_cost = t_cost;
  ctx.m_cost = m_cost;
  ctx.lanes = lanes;
  ctx.threads = lanes;
  ctx.version = ARGON2_VERSION_13;
  ctx.flags = ARGON2_DEFAULT_FLAGS;

  caml_enter_blocking_section();
  int rc = argon2_ctx(&ctx, Argon2_id);
  caml_leave_blocking_section();

  wipe_free(pwd, pwdlen);
  wipe_free(salt, saltlen);
  wipe_free(secret, secretlen);
  wipe_free(ad, adlen);
  if (rc != ARGON2_OK) {
    wipe_free(out, outlen);
    caml_failwith(argon2_error_message(rc));
  }
  v_out = caml_alloc_initialized_string(outlen, (const char *)out);
  wipe_free(out, outlen);
  CAMLreturn(v_out);
}
