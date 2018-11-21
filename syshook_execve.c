#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION( 3, 10, 0 )
struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};
#endif

struct kprobe kp;


static const char __user *get_user_arg_ptr( struct user_arg_ptr argv, int nr )
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if ( unlikely( argv.is_compat ) )
	{
		compat_uptr_t compat;

		if ( get_user( compat, argv.ptr.compat + nr ) )
			return(ERR_PTR( -EFAULT ) );

		return(compat_ptr( compat ) );
	}
#endif

	if ( get_user( native, argv.ptr.native + nr ) )
		return(ERR_PTR( -EFAULT ) );

	return(native);
}


static int tmp_count( struct user_arg_ptr argv, int max )
{
	int i = 0;

	if ( argv.ptr.native != NULL )
	{
		for (;; )
		{
			const char __user *p = get_user_arg_ptr( argv, i );

			if ( !p )
				break;

			if ( IS_ERR( p ) )
				return(-EFAULT);

			if ( i >= max )
				return(-E2BIG);
			++i;

			if ( fatal_signal_pending( current ) )
				return(-ERESTARTNOHAND);
			cond_resched();
		}
	}
	return(i);
}


int handler_pre( struct kprobe *p, struct pt_regs *regs )
{
	int			error			= 0, i = 0, len = 0, offset = 0, max_len = 0;
	const char __user	* native		= NULL;
	char			*total_argc_ptr		= NULL;
	char			*total_envpc_ptr	= NULL;
	char			*per_envp		= NULL;
	int			tmp_argc		= 0, total_argc_len = 0;
	int			tmp_envpc		= 0, total_envpc_len = 0;
	char			*tmp			= kmalloc( PATH_MAX, GFP_KERNEL );

	struct user_arg_ptr	argvx	= { .ptr.native = regs->si };
	struct user_arg_ptr	envpx	= { .ptr.native = regs->dx };

	tmp_argc = tmp_count( argvx, MAX_ARG_STRINGS );


	for ( i = 0; i < tmp_argc; i++ )
	{
		native = get_user_arg_ptr( argvx, i );
		if ( IS_ERR( native ) )
		{
			error = -EFAULT;
			goto err;
		}

		len = strnlen_user( native, MAX_ARG_STRLEN );
		if ( !len )
		{
			error = -EFAULT;
			goto err;
		}

		total_argc_len += len;
	}

	total_argc_ptr = kmalloc( total_argc_len + 16 * tmp_argc, GFP_ATOMIC );
	if ( !total_argc_ptr )
	{
		error = -ENOMEM;
		goto err;
	}
	memset( total_argc_ptr, 0, total_argc_len + 16 * tmp_argc );

	for ( i = 0; i < tmp_argc; i++ )
	{
		if ( i == 0 )
		{
			continue;
		}
		native = get_user_arg_ptr( argvx, i );
		if ( IS_ERR( native ) )
		{
			error = -EFAULT;
			goto err;
		}

		len = strnlen_user( native, MAX_ARG_STRLEN );
		if ( !len )
		{
			error = -EFAULT;
			goto err;
		}

		if ( offset + len > total_argc_len + 16 * tmp_argc )
		{
			break;
		}

		if ( copy_from_user( total_argc_ptr + offset, native, len ) )
		{
			error = -EFAULT;
			goto err;
		}
		offset				+= len - 1;
		*(total_argc_ptr + offset)	= ' ';
		offset				+= 1;
	}


	/*--------envpx--------------*/
	len		= 0;
	offset		= 0;
	tmp_envpc	= tmp_count( envpx, MAX_ARG_STRINGS );
	if ( tmp_envpc < 0 )
	{
		error = tmp_envpc;
		goto err;
	}

	for ( i = 0; i < tmp_envpc; i++ )
	{
		native = get_user_arg_ptr( envpx, i );
		if ( IS_ERR( native ) )
		{
			error = -EFAULT;
			goto err;
		}

		len = strnlen_user( native, MAX_ARG_STRLEN );
		if ( !len )
		{
			error = -EFAULT;
			goto err;
		}

		if ( len > max_len )
		{
			max_len = len;
		}

		total_envpc_len += len;
	}

	per_envp = kmalloc( max_len + 16, GFP_KERNEL );
	if ( !per_envp )
	{
		error = -ENOMEM;
		goto err;
	}

	total_envpc_ptr = kmalloc( total_envpc_len + 16 * tmp_envpc, GFP_KERNEL );
	if ( !total_envpc_ptr )
	{
		error = -ENOMEM;
		goto err;
	}
	memset( total_envpc_ptr, 0, total_envpc_len + 16 * tmp_envpc );

	for ( i = 0; i < tmp_envpc; i++ )
	{
		native = get_user_arg_ptr( envpx, i );
		if ( IS_ERR( native ) )
		{
			error = -EFAULT;
			goto err;
		}

		len = strnlen_user( native, MAX_ARG_STRLEN );
		if ( !len )
		{
			error = -EFAULT;
			goto err;
		}

		if ( offset + len > total_envpc_len + 16 * tmp_envpc )
		{
			break;
		}

		memset( per_envp, 0, max_len );
		if ( copy_from_user( per_envp, native, len ) )
		{
			error = -EFAULT;
			goto err;
		}

		if ( !strstr( per_envp, "PWD" ) && !strstr( per_envp, "LOGNAME" ) && !strstr( per_envp, "USER" ) )
		{
			continue;
		}

		if ( copy_from_user( total_envpc_ptr + offset, native, len ) )
		{
			error = -EFAULT;
			goto err;
		}
		offset				+= len - 1;
		*(total_envpc_ptr + offset)	= ' ';
		offset				+= 1;
	}


	printk( KERN_INFO "%s|%s|%u|%s|%d|%s\n", (char *) regs->di, total_argc_ptr, current->tgid, current->parent->comm, current->parent->tgid, total_envpc_ptr );


	/*
	 * printk(KERN_INFO "|pid: %6d |tgid: %6d | parent_filename = %10s| parent_tgid: %6d  |comm: %10s |filename = %10s|argv = %s \n",
	 *                      current->pid, current->tgid, current->parent->comm, current->parent->tgid  ,current->comm, (char *)regs->di ,total_argc_ptr);
	 */
	
err:
	if ( tmp )
	{
		kfree( tmp );
		tmp = NULL;
	}
	if ( per_envp )
	{
		kfree( per_envp );
		per_envp = NULL;
	}
	if ( total_argc_ptr )
	{
		kfree( total_argc_ptr );
		total_argc_ptr = NULL;
	}
	if ( total_envpc_ptr )
	{
		kfree( total_envpc_ptr );
		total_envpc_ptr = NULL;
	}
	return(0);
}


static __init int init_kprobe_sample( void )
{
	kp.symbol_name	= "sys_execve";
	kp.pre_handler	= handler_pre;
	register_kprobe( &kp );
	printk( KERN_INFO "---------------kprobe for execve--------------\n" );
	return(0);
}


static __exit void cleanup_kprobe_sample( void )
{
	unregister_kprobe( &kp );
}


module_init( init_kprobe_sample );
module_exit( cleanup_kprobe_sample );

MODULE_LICENSE( "GPL" );
