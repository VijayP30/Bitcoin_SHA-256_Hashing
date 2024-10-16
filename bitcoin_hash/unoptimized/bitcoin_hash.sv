module bitcoin_hash #(
    parameter integer NUM_OF_WORDS = 19
)(
    input logic  clk, reset_n, start,
    input logic [15:0] message_addr, output_addr,
    output logic        done, mem_clk, mem_we,
    output logic [15:0] mem_addr,
    output logic [31:0] mem_write_data,
    input logic [31:0] mem_read_data);

parameter num_nonces = 16;

enum logic [4:0] {
    IDLE,
    READ_BUFFER,
    READ,
    SETUP,
    SETUP_BUFFER,
    PHASE1,
    PHASE2,
    PHASE3,
    WRITE_SETUP,
    WRITE_BUFFER,
    WRITE
} state;

logic [31:0] hout[num_nonces];
logic [511:0] hs[num_nonces];

logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [255:0] h_in;
logic [255:0] p1_out, p2_out, p3_out;
logic [511:0] p3_in;
logic [511:0] p2_out_padded;
logic [511:0] p2_outs[num_nonces];
logic [31:0] message[32];  
logic [511:0] p1_message, p2_message;
logic [31:0] i, j, l, nonce;
logic [15:0] offset;
logic p1_done, p2_done, p3_done;
logic p1_start, p2_start, p3_start;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;

assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

assign nonce = i + 1;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

sha256 sha256_p1 (
    .clk(clk),
    .reset_n(reset_n),
    .start(p1_start),
    .done(p1_done),
    .h_out(p1_out),
    .h_block(h_in),
    .message(p1_message)
);

sha256 sha256_p2 (
    .clk(clk),
    .reset_n(reset_n),
    .start(p2_start),
    .done(p2_done),
    .h_out(p2_out),
    .h_block(p1_out),
    .message(p2_message)
);

sha256 sha256_p3 (
    .clk(clk),
    .reset_n(reset_n),
    .start(p3_start),
    .done(p3_done),
    .h_out(p3_out),
    .h_block(h_in),
    .message(p3_in)
);

// Student to add rest of the code here
always_ff @(posedge clk, negedge reset_n) begin 
    if (!reset_n) begin 
        cur_we <= 1'b0;
        state <= IDLE;
    end
    else begin 
        case (state) 
            IDLE: begin 
                if (start) begin 
                    h0 <= 32'h6a09e667;
                    h1 <= 32'hbb67ae85;
                    h2 <= 32'h3c6ef372;
                    h3 <= 32'ha54ff53a;
                    h4 <= 32'h510e527f;
                    h5 <= 32'h9b05688c;
                    h6 <= 32'h1f83d9ab;
                    h7 <= 32'h5be0cd19;
                    offset <= 0;
                    i <= 0;
                    j <= 0;
                    l <= 0;
                    state <= READ_BUFFER;
                    cur_we <= 0;
                    cur_addr <= message_addr;

                end
                else begin 
                    state <= IDLE;
                end
            end

            READ_BUFFER: begin
                state <= READ;
            end

            READ: begin
                if (offset < NUM_OF_WORDS) begin
                    message[offset] <= mem_read_data;
                    offset <= offset + 1;
                    state <= READ_BUFFER;
                end else begin
                    message[19] <= 32'h00000000; // initial nonce
                    message[20] <= 32'h80000000;  // '1' delimiter
                    for (int k = 21; k < 31; k++) begin  // 0 padding
                    message[k] <= 32'h00000000;
                    end
                    message[31] <= 32'd640;  // 640 bits
                    offset <= 0;
                    state <= SETUP_BUFFER;
                end
            end

            SETUP: begin 
                if (l < 16) begin 
                    p1_message[31:0] <= message[l];
                    p2_message[31:0] <= message[l+16];
                    l <= l + 1;
                    state <= SETUP_BUFFER;
                end
                
            end

            SETUP_BUFFER: begin
                if (l < 16) begin  
                    p1_message <= p1_message << 32;
                    p2_message <= p2_message << 32;
                    state <= SETUP;
                end
                else begin
                    h_in <= {h7, h6, h5, h4, h3, h2, h1, h0};
                    p1_start <= 1'b1;
                    state <= PHASE1;
                end
            end

            PHASE1: begin 
                p1_start <= 1'b0;
                if (p1_done) begin 
                    p2_start <= 1'b1;
                    state <= PHASE2;
                end
                else begin 
                    state <= PHASE1;
                end
            end

            PHASE2: begin
                p2_start <= 1'b0; 
                if (i < num_nonces) begin 
                    if (p2_done) begin 
                        i <= i + 1;
                        p2_start <= 1'b1;
                        p2_message[415:384] <= nonce;
                        p2_outs[i] <= {p2_out[31:0], p2_out[63:32], p2_out[95:64], p2_out[127:96], p2_out[159:128], p2_out[191:160], p2_out[223:192], p2_out[255:224], 1'b1, 191'b0, 64'd256};
                    end
                    state <= PHASE2;
                end
                else begin
                    p3_start <= 1'b1;
                    p3_in <= p2_outs[0];
                    state <= PHASE3;
                end
            end

            PHASE3: begin
                p3_start <= 1'b0; 
                if (j < num_nonces) begin 
                    if (p3_done) begin 
                        j <= j + 1;
                        p3_start <= 1'b1;
                        p3_in <= p2_outs[j + 1];
                        hs[j] <= p3_out;
                    end
                    state <= PHASE3;
                end
                else begin
                    state <= WRITE_SETUP;
                end
            end

            WRITE_SETUP: begin 
                cur_addr <= output_addr;
                offset <= 0;
                for (int k = 0; k < 16; k++) begin 
                    hout[k] <= hs[k][31:0];
                end
                state <= WRITE;
            end

            WRITE_BUFFER: begin
            offset <= offset + 1;
            state  <= WRITE;
            end

            WRITE: begin
            if (offset < num_nonces) begin
                cur_write_data <= hout[offset];
                cur_we <= 1;
                state  <= WRITE_BUFFER;
            end else begin
                state <= IDLE;
            end
            end
        endcase
    end
end

assign done = (state == IDLE);

endmodule
