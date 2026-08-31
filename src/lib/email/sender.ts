import { and, eq } from "drizzle-orm";
import { getDb } from "@/db";
import { domains, mailboxes, users } from "@/db/schema";
import { getMailboxAccessLevel } from "@/lib/mailboxes/access";
import { formatEmailAddress, getEmailAddress } from "@/lib/email/address";
import { getMailboxDomainAddresses } from "@/lib/mailboxes/domain-addresses";

export async function getAuthorizedSenderAddress(
	env: CloudflareEnv,
	input: {
		userId: string;
		from: string;
		mailboxId?: string | null;
	},
): Promise<{ fromAddr: string; mailboxId: string }> {
	const db = getDb(env);
	let targetMailboxId = input.mailboxId;

	if (!targetMailboxId) {
		const requestedAddress = getEmailAddress(input.from).toLowerCase();
		const [localPart, hostname] = requestedAddress.split("@");
		if (localPart && hostname) {
			const [match] = await db
				.select({ id: mailboxes.id })
				.from(mailboxes)
				.innerJoin(domains, eq(mailboxes.domainId, domains.id))
				.where(and(eq(mailboxes.localPart, localPart), eq(domains.hostname, hostname)))
				.limit(1);
			if (match) targetMailboxId = match.id;
		}
	}

	if (!targetMailboxId) throw new Error("Mailbox is required or could not be resolved from sender address");

	const [mailbox] = await db
		.select({
		localPart: mailboxes.localPart,
		displayName: mailboxes.displayName,
		hostname: domains.hostname,
		domainId: mailboxes.domainId,
		useAllDomains: mailboxes.useAllDomains,
			id: mailboxes.id,
		})
		.from(mailboxes)
		.innerJoin(domains, eq(mailboxes.domainId, domains.id))
		.where(eq(mailboxes.id, targetMailboxId))
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

	if (access.canSendAs) {
		return {
			fromAddr: formatEmailAddress(senderAddress, mailbox.displayName),
			mailboxId: mailbox.id,
		};
	}

	const mailboxName = mailbox.displayName || senderAddress;
	return {
		fromAddr: formatEmailAddress(senderAddress, `${actor.name} on behalf of ${mailboxName}`),
		mailboxId: mailbox.id,
	};
}
