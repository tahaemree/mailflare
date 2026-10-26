import { and, eq } from "drizzle-orm";
import { getDb } from "@/db";
import { domains, mailboxAliases, mailboxes, users } from "@/db/schema";
import { getMailboxAccessLevel } from "@/lib/mailboxes/access";
import { formatEmailAddress, getEmailAddress } from "@/lib/email/address";
import { getMailboxDomainAddresses } from "@/lib/mailboxes/domain-addresses";
import { resolveMailboxDisplayName } from "@/lib/profile/identity-utils";

/**
 * Find the mailbox that owns a sender address, for API callers that send `from` without a
 * `mailboxId`. Matches the mailbox's own address first, then its aliases. This only picks a
 * candidate; `getAuthorizedSenderAddress` still checks that the caller may send from it.
 */
export async function resolveSenderMailboxId(env: CloudflareEnv, from: string): Promise<string | null> {
	const address = getEmailAddress(from).toLowerCase();
	const at = address.lastIndexOf("@");
	if (at <= 0 || at === address.length - 1) return null;
	const localPart = address.slice(0, at);
	const hostname = address.slice(at + 1);

	const db = getDb(env);
	const [mailbox] = await db
		.select({ id: mailboxes.id })
		.from(mailboxes)
		.innerJoin(domains, eq(mailboxes.domainId, domains.id))
		.where(and(eq(mailboxes.localPart, localPart), eq(domains.hostname, hostname)))
		.limit(1);
	if (mailbox) return mailbox.id;

	const [alias] = await db
		.select({ id: mailboxAliases.mailboxId })
		.from(mailboxAliases)
		.innerJoin(domains, eq(mailboxAliases.domainId, domains.id))
		.where(and(eq(mailboxAliases.localPart, localPart), eq(domains.hostname, hostname)))
		.limit(1);
	return alias?.id ?? null;
}

export async function getAuthorizedSenderAddress(
	env: CloudflareEnv,
	input: {
		userId: string;
		from: string;
		mailboxId?: string | null;
	},
): Promise<{ fromAddr: string; mailboxId: string }> {
	if (!input.mailboxId) throw new Error("Mailbox is required");

	const db = getDb(env);
	const [mailbox] = await db
		.select({
		localPart: mailboxes.localPart,
		displayName: mailboxes.displayName,
		type: mailboxes.type,
		ownerName: users.name,
		ownerEmail: users.email,
		hostname: domains.hostname,
		domainId: mailboxes.domainId,
		useAllDomains: mailboxes.useAllDomains,
			id: mailboxes.id,
		})
		.from(mailboxes)
		.innerJoin(domains, eq(mailboxes.domainId, domains.id))
		.innerJoin(users, eq(mailboxes.userId, users.id))
		.where(eq(mailboxes.id, input.mailboxId))
		.limit(1);

	if (!mailbox) throw new Error("Mailbox not found");
	const [actor] = await db.select().from(users).where(eq(users.id, input.userId)).limit(1);
	if (!actor || actor.disabled) throw new Error("Sender account not found");

	const access = await getMailboxAccessLevel(db, actor, mailbox.id);
	if (!access?.canSendOnBehalf) {
		throw new Error("You do not have permission to send from this mailbox");
	}

	const requestedAddress = getEmailAddress(input.from);
	const permittedAddresses = await getMailboxDomainAddresses(db, mailbox);
	if (!permittedAddresses.includes(requestedAddress.toLowerCase())) {
		throw new Error("Sender address does not match the selected mailbox");
	}
	const senderAddress = requestedAddress.toLowerCase();
	// The primary mailbox sends under the account name; every other mailbox
	// sends under its own.
	const senderName = resolveMailboxDisplayName(mailbox, mailbox.ownerEmail, mailbox.ownerName);

	if (access.canSendAs) {
		return {
			fromAddr: formatEmailAddress(senderAddress, senderName),
			mailboxId: mailbox.id,
		};
	}

	const mailboxName = senderName || senderAddress;
	return {
		fromAddr: formatEmailAddress(senderAddress, `${actor.name} on behalf of ${mailboxName}`),
		mailboxId: mailbox.id,
	};
}
