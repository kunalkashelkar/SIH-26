// Next.js App Router route handler and page definitions
export async function GET(request: Request) {
  return Response.json({ status: "ok" });
}

export async function POST(request: Request) {
  const body = await request.json();
  return Response.json({ created: body });
}
