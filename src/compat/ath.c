#include <gcrypt-internal.h>

#include "ath.h"

static struct gcry_thread_cbs ops;

enum ath_thread_option
  {
    ATH_THREAD_OPTION_DEFAULT = 0,
    ATH_THREAD_OPTION_USER = 1,
    ATH_THREAD_OPTION_PTH = 2,
    ATH_THREAD_OPTION_PTHREAD = 3
  };

static void
ath_ops_pass_to_core (struct gcry_thread_cbs *ath_ops)
{
  struct gcry_core_handler_ath ath;

  ath.init = ath_ops->init;
  ath.mutex_init = ath_ops->mutex_init;
  ath.mutex_destroy = ath_ops->mutex_destroy;
  ath.mutex_lock = ath_ops->mutex_lock;
  ath.mutex_unlock = ath_ops->mutex_unlock;
  ath.read = ath_ops->read;
  ath.write = ath_ops->write;
  ath.select = ath_ops->select;
  ath.waitpid = ath_ops->waitpid;
  ath.accept = ath_ops->accept;
  ath.connect = ath_ops->connect;
  ath.sendmsg = ath_ops->sendmsg;
  ath.recvmsg = ath_ops->recvmsg;

  gcry_core_set_handler_ath (context, &ath);
}

/* Initialize the locking library.  Returns 0 if the operation was
   successful, EINVAL if the operation table was invalid and EBUSY if
   we already were initialized.  */
gpg_error_t
ath_install (struct gcry_thread_cbs *ath_ops, int check_only)
{
  if (check_only)
    {
      enum ath_thread_option option = ATH_THREAD_OPTION_DEFAULT;
      
      /* Check if the requested thread option is compatible to the
	 thread option we are already committed to.  */
      if (ath_ops)
	option = ath_ops->option;

      if (!context->handler.ath.ops_set && option)
	return GPG_ERR_NOT_SUPPORTED;

      if (ops.option == ATH_THREAD_OPTION_USER
	  || option == ATH_THREAD_OPTION_USER
	  || ops.option != option)
	return GPG_ERR_NOT_SUPPORTED;

      return 0;
    }
    
  if (ath_ops)
    {
      /* It is convenient to not require DESTROY.  */
      if (!ath_ops->mutex_init || !ath_ops->mutex_lock
	  || !ath_ops->mutex_unlock)
	return GPG_ERR_INV_ARG;

      ops = *ath_ops;
      ath_ops_pass_to_core (ath_ops);
    }

  return 0;
}

/* END. */
